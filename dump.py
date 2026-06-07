#!/usr/bin/env python3
import argparse
import io
import json
import re
import struct
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    print("Missing dependency: pip install pefile", file=sys.stderr)
    raise SystemExit(1)


RT_RCDATA = 10
NUITKA_CONSTANT_BLOB_ID = 3
NUITKA_ONEFILE_PAYLOAD_ID = 27


class ExtractionError(RuntimeError):
    pass


def _load_pe(filename: Path | None = None, data: bytes | None = None):
    if filename is not None:
        pe = pefile.PE(str(filename), fast_load=False)
    else:
        pe = pefile.PE(data=data, fast_load=False)

    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )
    return pe


def read_rcdata_resource_from_pe(pe, resource_id: int) -> tuple[bytes, int] | None:
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None

    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if not hasattr(type_entry, "directory"):
            continue

        if type_entry.struct.Id != RT_RCDATA:
            continue

        for name_entry in type_entry.directory.entries:
            if not hasattr(name_entry, "directory"):
                continue

            if name_entry.struct.Id != resource_id:
                continue

            for lang_entry in name_entry.directory.entries:
                data_rva = lang_entry.data.struct.OffsetToData
                data_size = lang_entry.data.struct.Size
                data_offset = pe.get_offset_from_rva(data_rva)
                data = pe.__data__[data_offset : data_offset + data_size]
                return data, lang_entry.struct.Id

    return None


def read_rcdata_resource(filename: Path, resource_id: int) -> tuple[bytes, int] | None:
    pe = _load_pe(filename=filename)
    return read_rcdata_resource_from_pe(pe, resource_id)


# ---------------------------------------------------------------------------
# In-section constant blob (MinGW / modern Nuitka backends).
#
# Newer Nuitka links the constants blob straight into a data section (.rdata)
# as a linked-in symbol instead of exposing it as RT_RCDATA ID 3. The blob is
# still the same top-level format:
#     <name>\0 <u32 little-endian size> <size bytes>   (repeated)
# and its first section is reliably named ".bytecode". We anchor on that, then
# walk sections forward, bounded by the end of the containing raw section,
# until an entry stops looking like a valid (name, size) pair.
#
# If a build retains no bytecode modules there is no ".bytecode" section. In
# that case we fall back to a generic scan: probe every plausible top-level
# section start in the read-only data sections and keep the one whose forward
# walk chains the most bytes (the real blob dwarfs any random false match).
# ---------------------------------------------------------------------------

_BLOB_ANCHOR = b".bytecode\x00"
_MAX_SECTION_NAME = 256

# A top-level section name as it appears just before its u32 size: a dotted
# module name (or ".bytecode"), NUL-terminated.
_BLOB_NAME_RE = re.compile(rb"[A-Za-z_.][A-Za-z0-9_.]{0,127}\x00")
_GENERIC_DATA_SECTIONS = (b".rdata", b".data")
_GENERIC_MIN_COVERAGE = 4096  # ignore short accidental chains


def _blob_name_is_valid(name_bytes: bytes) -> bool:
    # Section names are dotted module names, ".bytecode", or "" (global).
    if name_bytes == b"":
        return True
    if len(name_bytes) > _MAX_SECTION_NAME:
        return False
    return all(0x20 <= c < 0x7F for c in name_bytes)


def _walk_top_level_blob(data: bytes, start: int, hard_end: int) -> int:
    """Return the file offset just past the last valid top-level section."""
    offset = start
    saw_section = False

    while offset < hard_end:
        nul = data.find(b"\0", offset)
        if nul < 0 or nul >= hard_end:
            break

        name_bytes = data[offset:nul]
        if not _blob_name_is_valid(name_bytes):
            break

        size_off = nul + 1
        if size_off + 4 > hard_end:
            break

        size = struct.unpack_from("<I", data, size_off)[0]
        body_off = size_off + 4
        if size > hard_end - body_off:
            break

        saw_section = True
        offset = body_off + size

        # Conventional empty-name terminator.
        if name_bytes == b"" and size == 0:
            break

    return offset if saw_section else start


def _section_raw_end(pe, file_offset: int) -> int:
    """End of the raw section containing file_offset (or EOF)."""
    data_len = len(pe.__data__)
    for section in pe.sections:
        raw_start = section.PointerToRawData
        raw_end = raw_start + section.SizeOfRawData
        if raw_start <= file_offset < raw_end:
            return raw_end
    return data_len


def _generic_blob_start(pe) -> tuple[int, int] | None:
    """Find the blob start when there is no ".bytecode" anchor.

    Probes every plausible top-level section start inside the read-only data
    sections and returns (start, end) for the candidate whose forward walk
    chains the most bytes. Candidates inside an already-found blob are skipped.
    """
    data = pe.__data__
    best = None  # (coverage, start, end)

    for section in pe.sections:
        if section.Name.rstrip(b"\x00") not in _GENERIC_DATA_SECTIONS:
            continue

        raw_start = section.PointerToRawData
        raw_end = raw_start + section.SizeOfRawData
        segment = data[raw_start:raw_end]

        for match in _BLOB_NAME_RE.finditer(segment):
            off = raw_start + match.start()

            # Must sit on a section boundary (previous byte is a NUL terminator).
            if off > raw_start and data[off - 1] != 0:
                continue

            # Skip matches that fall inside a blob we already accepted.
            if best is not None and best[1] <= off < best[2]:
                continue

            size_off = raw_start + match.end()  # match.end() is just past the NUL
            if size_off + 4 > raw_end:
                continue

            size = struct.unpack_from("<I", data, size_off)[0]
            if size == 0 or size > raw_end - (size_off + 4):
                continue

            end = _walk_top_level_blob(data, off, raw_end)
            coverage = end - off
            if coverage < _GENERIC_MIN_COVERAGE:
                continue

            if best is None or coverage > best[0]:
                best = (coverage, off, end)

    if best is None:
        return None
    return best[1], best[2]


def _looks_like_constants_blob(blob: bytes, min_parsed: int = 4) -> bool:
    """Confirm a carved region really is a Nuitka constants blob.

    The structural walk only checks that bytes chain as <name>\\0<size><data>;
    ordinary DLLs/PYDs can satisfy that by accident. This re-parses the region
    with the constants reader and requires at least ``min_parsed`` top-level
    sections that decode as genuine constants streams (count + tag values +
    end tag). Random data essentially never decodes even once.
    """
    try:
        import read_constant_blob as rcb
    except ImportError:
        return _structural_constants_check(blob, min_parsed)

    try:
        sections = rcb.split_top_level_blob(blob)
    except Exception:
        return False

    if len(sections) < min_parsed:
        return False

    for blob_format in ("fixed", "legacy"):
        good = 0
        for name, section_data in sections:
            try:
                rcb.parse_section(name, section_data, blob_format=blob_format)
            except Exception:
                continue
            good += 1
            if good >= min_parsed:
                return True

    return False


def _structural_constants_check(blob: bytes, min_parsed: int) -> bool:
    """Fallback validation when read_constant_blob is unavailable."""
    ident = re.compile(rb"\A[A-Za-z_.][A-Za-z0-9_.]*\Z")
    offset = 0
    total = 0
    named = 0

    while offset < len(blob):
        nul = blob.find(b"\0", offset)
        if nul < 0 or nul + 5 > len(blob):
            break
        name = blob[offset:nul]
        size = struct.unpack_from("<I", blob, nul + 1)[0]
        body = nul + 5
        if size > len(blob) - body:
            break
        total += 1
        if name in (b"", b".bytecode") or ident.match(name):
            named += 1
        offset = body + size

    return total >= min_parsed and named >= max(min_parsed, total // 2)


def carve_constant_blob_from_pe(pe) -> tuple[bytes, int, int] | None:
    """Locate the linked-in constants blob in a PE's section data.

    Tries the ".bytecode"-anchored region first, then a generic max-coverage
    scan, and accepts only a candidate that validates as a real constants blob.
    Returns (blob_bytes, file_start, file_end) or None.
    """
    data = pe.__data__
    candidates = []

    start = data.find(_BLOB_ANCHOR)
    if start >= 0:
        end = _walk_top_level_blob(data, start, _section_raw_end(pe, start))
        if end > start:
            candidates.append((start, end))

    generic = _generic_blob_start(pe)
    if generic is not None and generic not in candidates:
        candidates.append(generic)

    for start, end in candidates:
        blob = data[start:end]
        if _looks_like_constants_blob(blob):
            return blob, start, end

    return None


def read_section_constant_blob_from_pe(pe) -> tuple[bytes, int | None] | None:
    """RT_RCDATA-resource-compatible signature: (blob, lang_id=None)."""
    carved = carve_constant_blob_from_pe(pe)
    if carved is None:
        return None
    blob, _start, _end = carved
    return blob, None


def read_section_constant_blob(filename: Path) -> tuple[bytes, int | None] | None:
    pe = _load_pe(filename=filename)
    return read_section_constant_blob_from_pe(pe)


def resolve_constant_blob_from_pe(pe) -> tuple[bytes, int | None, str] | None:
    """Try RT_RCDATA ID 3 first, then fall back to in-section carving.

    Returns (blob, lang_id, method) where method is "resource_id3" or
    "rdata_section_carve".

    A onefile wrapper (RT_RCDATA ID 27) is itself a Nuitka program with its
    own small constants blob, but the real application lives in its payload.
    We must NOT carve the wrapper's loader blob here, otherwise the caller
    would stop before extracting and analysing the inner backend. Decline so
    the onefile-extraction path runs instead.
    """
    resource = read_rcdata_resource_from_pe(pe, NUITKA_CONSTANT_BLOB_ID)
    if resource is not None:
        blob, lang_id = resource
        return blob, lang_id, "resource_id3"

    if is_onefile_payload_present(pe):
        return None

    carved = read_section_constant_blob_from_pe(pe)
    if carved is not None:
        blob, lang_id = carved
        return blob, lang_id, "rdata_section_carve"

    return None


def resolve_constant_blob(filename: Path) -> tuple[bytes, int | None, str] | None:
    pe = _load_pe(filename=filename)
    return resolve_constant_blob_from_pe(pe)


def dump_blob(blob: bytes, output_path: Path, label: str, source: str, lang_id: int | None = None) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(blob)

    print(f"Dumped {label}")
    print(f"Input : {source}")
    print(f"Output: {output_path}")
    print(f"Size  : {len(blob)} bytes")
    if lang_id is not None:
        print(f"Lang  : {lang_id}")


# Compressed Nuitka onefile payloads start with "KAY" immediately followed by
# a zstd frame magic. This composite signature lets us locate a payload that is
# stored inside a section (not as RT_RCDATA ID 27 and not as a file overlay).
_ONEFILE_COMPRESSED_SIG = b"KAY" + b"\x28\xb5\x2f\xfd"


def locate_onefile_payload_from_pe(pe) -> bytes | None:
    """Return raw onefile payload bytes (beginning with KAX/KAY), or None.

    Prefers RT_RCDATA ID 27; falls back to scanning the image for the
    compressed-payload signature. Trailing bytes after the payload are fine:
    decompress_onefile_body() stops at the end of the zstd frame.
    """
    resource = read_rcdata_resource_from_pe(pe, NUITKA_ONEFILE_PAYLOAD_ID)
    if resource is not None:
        return resource[0]

    data = pe.__data__
    index = data.find(_ONEFILE_COMPRESSED_SIG)
    if index >= 0:
        return data[index:]

    return None


def locate_onefile_payload(filename: Path) -> bytes | None:
    return locate_onefile_payload_from_pe(_load_pe(filename=filename))


def is_onefile_payload_present(pe) -> bool:
    """True if this PE is a onefile wrapper (resource ID 27 or KAY signature)."""
    if read_rcdata_resource_from_pe(pe, NUITKA_ONEFILE_PAYLOAD_ID) is not None:
        return True
    return pe.__data__.find(_ONEFILE_COMPRESSED_SIG) >= 0


def get_onefile_payload_region(resource_data: bytes) -> bytes:
    if not resource_data.startswith((b"KAX", b"KAY")):
        raise ExtractionError("RT_RCDATA ID 27 does not start with a Nuitka onefile header")

    if len(resource_data) >= 11:
        footer_size = struct.unpack_from("<Q", resource_data, len(resource_data) - 8)[0]
        if footer_size == len(resource_data) - 8:
            return resource_data[:footer_size]

    return resource_data


def decompress_onefile_body(payload_region: bytes) -> bytes:
    header = payload_region[:3]
    body = payload_region[3:]

    if header == b"KAX":
        return body

    if header != b"KAY":
        raise ExtractionError(f"unsupported Nuitka onefile header: {header!r}")

    try:
        import zstandard as zstd
    except ImportError:
        print("Missing dependency for compressed onefile payload: pip install zstandard", file=sys.stderr)
        raise SystemExit(1)

    # decompressobj() reads exactly one zstd frame and stops, tolerating any
    # trailing footer/padding bytes — and also unrelated tail bytes when the
    # payload was located by magic scan rather than an exact resource slice.
    try:
        return zstd.ZstdDecompressor().decompressobj().decompress(body)
    except zstd.ZstdError as exc:
        raise ExtractionError(f"failed to decompress zstd onefile payload: {exc}")


def read_utf16le_zstring(data: bytes, offset: int) -> tuple[str, int]:
    end = offset

    while end + 1 < len(data):
        if data[end : end + 2] == b"\0\0":
            raw = data[offset:end]
            return raw.decode("utf-16le"), end + 2
        end += 2

    raise ExtractionError("unterminated UTF-16LE filename in onefile payload")


def safe_payload_path(base_dir: Path, payload_name: str) -> Path:
    parts = []

    for part in payload_name.replace("\\", "/").split("/"):
        if not part or part in (".", ".."):
            continue
        if part.endswith(":"):
            continue
        parts.append(part)

    if not parts:
        raise ExtractionError(f"unsafe or empty payload filename: {payload_name!r}")

    return base_dir.joinpath(*parts)


def parse_payload_entries(payload_data: bytes, checksums: bool) -> list[tuple[str, bytes, int | None]]:
    entries = []
    offset = 0

    while offset < len(payload_data):
        filename, offset = read_utf16le_zstring(payload_data, offset)

        if filename == "":
            return entries

        if offset + 8 > len(payload_data):
            raise ExtractionError(f"truncated size field for payload entry {filename!r}")

        file_size = struct.unpack_from("<Q", payload_data, offset)[0]
        offset += 8

        checksum = None
        if checksums:
            if offset + 4 > len(payload_data):
                raise ExtractionError(f"truncated checksum field for payload entry {filename!r}")
            checksum = struct.unpack_from("<I", payload_data, offset)[0]
            offset += 4

        if file_size > len(payload_data) - offset:
            raise ExtractionError(
                f"payload entry {filename!r} claims {file_size} bytes, "
                f"but only {len(payload_data) - offset} bytes remain"
            )

        file_data = payload_data[offset : offset + file_size]
        offset += file_size
        entries.append((filename, file_data, checksum))

    raise ExtractionError("payload ended before empty filename terminator")


def parse_payload_entries_auto(payload_data: bytes, checksum_mode: str) -> tuple[list[tuple[str, bytes, int | None]], bool]:
    if checksum_mode == "yes":
        return parse_payload_entries(payload_data, checksums=True), True

    if checksum_mode == "no":
        return parse_payload_entries(payload_data, checksums=False), False

    no_checksum_error = None
    try:
        return parse_payload_entries(payload_data, checksums=False), False
    except ExtractionError as exc:
        no_checksum_error = exc

    try:
        return parse_payload_entries(payload_data, checksums=True), True
    except ExtractionError as checksum_error:
        raise ExtractionError(
            "failed to parse payload with and without checksums; "
            f"without checksums: {no_checksum_error}; with checksums: {checksum_error}"
        )


def extract_entries(entries: list[tuple[str, bytes, int | None]], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted = []

    for filename, file_data, _checksum in entries:
        output_path = safe_payload_path(output_dir, filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(file_data)
        extracted.append(output_path)

    return extracted


def find_constant_blob_in_payload_entries(entries: list[tuple[str, bytes, int | None]]) -> tuple[str, bytes, int | None] | None:
    for filename, file_data, _checksum in entries:
        if not file_data.startswith(b"MZ"):
            continue

        try:
            pe = _load_pe(data=file_data)
        except pefile.PEFormatError:
            continue

        resolved = resolve_constant_blob_from_pe(pe)
        if resolved is None:
            continue

        blob, lang_id, _method = resolved
        return filename, blob, lang_id

    return None


_METHOD_LABELS = {
    "resource_id3": "RT_RCDATA ID 3 constant blob",
    "rdata_section_carve": "in-section (.rdata) linked constant blob",
}


def dump_direct_constant_blob(input_path: Path, output_path: Path) -> bool:
    resolved = resolve_constant_blob(input_path)
    if resolved is None:
        return False

    blob, lang_id, method = resolved
    dump_blob(blob, output_path, _METHOD_LABELS.get(method, method), str(input_path), lang_id)
    return True


def dump_from_onefile(input_path: Path, output_path: Path, payload_output: Path, extract_dir: Path, checksum_mode: str) -> None:
    payload_blob = locate_onefile_payload(input_path)
    if payload_blob is None:
        raise ExtractionError(
            "no Nuitka onefile payload found "
            "(no RT_RCDATA ID 27 and no KAY payload signature)"
        )

    dump_blob(
        payload_blob,
        payload_output,
        "Nuitka onefile payload",
        str(input_path),
        None,
    )

    payload_region = get_onefile_payload_region(payload_blob)
    payload_data = decompress_onefile_body(payload_region)
    entries, used_checksums = parse_payload_entries_auto(payload_data, checksum_mode)
    extracted_paths = extract_entries(entries, extract_dir)

    print(f"Extracted payload files: {len(extracted_paths)}")
    print(f"Extract dir            : {extract_dir}")
    print(f"Parsed checksums       : {'yes' if used_checksums else 'no'}")

    result = find_constant_blob_in_payload_entries(entries)
    if result is None:
        manifest_path = extract_dir / "payload_manifest.json"
        manifest_path.write_text(
            json.dumps(
                [
                    {"name": filename, "size": len(file_data), "has_checksum": checksum is not None}
                    for filename, file_data, checksum in entries
                ],
                indent=2,
            ),
            encoding="utf-8",
        )
        raise ExtractionError(
            "no extracted PE file contains RT_RCDATA ID 3; "
            f"payload manifest written to {manifest_path}"
        )

    backend_name, constant_blob, lang_id = result
    dump_blob(
        constant_blob,
        output_path,
        f"RT_RCDATA ID 3 constant blob from payload PE {backend_name!r}",
        str(input_path),
        lang_id,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dump Nuitka constant blob ID 3 directly or through onefile payload ID 27."
    )
    parser.add_argument("exe", type=Path, help="Nuitka-built backend EXE/DLL or outer onefile EXE")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("constant_blob_id3.bin"),
        help="Output filename for RT_RCDATA ID 3",
    )
    parser.add_argument(
        "--payload-output",
        type=Path,
        default=None,
        help="Output filename for raw onefile RT_RCDATA ID 27",
    )
    parser.add_argument(
        "--extract-dir",
        type=Path,
        default=None,
        help="Directory for extracted onefile payload files",
    )
    parser.add_argument(
        "--checksums",
        choices=("auto", "yes", "no"),
        default="auto",
        help="Whether payload entries contain CRC32 checksums. Default auto handles normal temporary onefile builds.",
    )
    parser.add_argument(
        "--onefile-only",
        action="store_true",
        help="Skip direct ID 3 probing and force ID 27 payload extraction.",
    )

    args = parser.parse_args()

    input_path = args.exe
    payload_output = args.payload_output or input_path.with_name(input_path.stem + "_resource_id27.bin")
    extract_dir = args.extract_dir or input_path.with_name(input_path.stem + "_payload")

    try:
        if not args.onefile_only and dump_direct_constant_blob(input_path, args.output):
            return

        dump_from_onefile(
            input_path=input_path,
            output_path=args.output,
            payload_output=payload_output,
            extract_dir=extract_dir,
            checksum_mode=args.checksums,
        )
    except (ExtractionError, pefile.PEFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
