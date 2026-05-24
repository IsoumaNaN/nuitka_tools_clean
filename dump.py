#!/usr/bin/env python3
import argparse
import io
import json
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


def dump_blob(blob: bytes, output_path: Path, label: str, source: str, lang_id: int | None = None) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(blob)

    print(f"Dumped {label}")
    print(f"Input : {source}")
    print(f"Output: {output_path}")
    print(f"Size  : {len(blob)} bytes")
    if lang_id is not None:
        print(f"Lang  : {lang_id}")


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

    last_error = None
    candidates = [body]

    # Windows payloads can contain up to 7 zero padding bytes before the footer.
    for trim_count in range(1, 8):
        if len(body) >= trim_count and body[-trim_count:] == b"\0" * trim_count:
            candidates.append(body[:-trim_count])

    for candidate in candidates:
        try:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(io.BytesIO(candidate)) as reader:
                return reader.read()
        except zstd.ZstdError as exc:
            last_error = exc

    raise ExtractionError(f"failed to decompress zstd onefile payload: {last_error}")


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


def find_constant_blob_in_payload_entries(entries: list[tuple[str, bytes, int | None]]) -> tuple[str, bytes, int] | None:
    for filename, file_data, _checksum in entries:
        if not file_data.startswith(b"MZ"):
            continue

        try:
            pe = _load_pe(data=file_data)
        except pefile.PEFormatError:
            continue

        resource = read_rcdata_resource_from_pe(pe, NUITKA_CONSTANT_BLOB_ID)
        if resource is None:
            continue

        blob, lang_id = resource
        return filename, blob, lang_id

    return None


def dump_direct_constant_blob(input_path: Path, output_path: Path) -> bool:
    resource = read_rcdata_resource(input_path, NUITKA_CONSTANT_BLOB_ID)
    if resource is None:
        return False

    blob, lang_id = resource
    dump_blob(blob, output_path, "RT_RCDATA ID 3 constant blob", str(input_path), lang_id)
    return True


def dump_from_onefile(input_path: Path, output_path: Path, payload_output: Path, extract_dir: Path, checksum_mode: str) -> None:
    resource = read_rcdata_resource(input_path, NUITKA_ONEFILE_PAYLOAD_ID)
    if resource is None:
        raise ExtractionError("RT_RCDATA resource ID 27 not found")

    payload_blob, payload_lang_id = resource
    dump_blob(
        payload_blob,
        payload_output,
        "RT_RCDATA ID 27 onefile payload",
        str(input_path),
        payload_lang_id,
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
