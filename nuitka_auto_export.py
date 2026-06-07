#!/usr/bin/env python3
"""
Export static-analysis artifacts from Nuitka-built PE files.

This automates the mechanical parts:
- detect backend vs onefile wrapper
- dump onefile RT_RCDATA ID 27 when present
- extract onefile payload entries
- find backend PE files containing Nuitka RT_RCDATA ID 3
- dump and parse the constant blob
- export per-module constants, BlobData, marshal/.pyc candidates
- generate an IDA helper script that finds string xrefs for AI-assisted analysis
python nuitka_auto_export.py target.exe -o target_export

python nuitka_auto_export.py target.exe -o target_export --onefile-only

"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import marshal
import re
import shutil
import struct
import sys
from pathlib import Path
from typing import Any

try:
    import pefile
except ImportError:
    print("Missing dependency: pip install pefile", file=sys.stderr)
    raise SystemExit(1)

try:
    import dump as nuitka_dump
    import read_constant_blob as nuitka_blob
except ImportError as exc:
    print(
        "This script must be placed next to dump.py and read_constant_blob.py",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc


RT_RCDATA = 10
NUITKA_CONSTANT_BLOB_ID = 3
NUITKA_ONEFILE_PAYLOAD_ID = 27

SECRET_PATTERNS = [
    # (re.compile(r"(Token\s+)[A-Za-z0-9._~+/=:-]+"), r"\1<redacted>"),
    # (re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=:-]+"), r"\1<redacted>"),
    # (
    #     re.compile(r"(['\"]Authorization['\"]\s*:\s*['\"](?:Token|Bearer)\s+)[^'\"]+"),
    #     r"\1<redacted>",
    # ),
]


def redact_text(text: str, enabled: bool) -> str:
    if not enabled:
        return text

    result = text
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def safe_name(value: str, fallback: str = "item") -> str:
    value = value.replace("\\", "_").replace("/", "_").replace(":", "_")
    value = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)
    value = value.strip("._-")
    return value or fallback


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode("utf-8", "backslashreplace"))


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, indent=2, ensure_ascii=False))


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def normalize_value(value: Any, redact: bool) -> Any:
    if isinstance(value, nuitka_blob.BlobDataValue):
        return value.as_summary()

    if isinstance(value, nuitka_blob.BytesValue):
        return {
            **value.as_summary(),
            "preview": redact_text(value.as_summary()["preview"], redact),
        }

    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "size": len(value),
            "sha256": sha256_bytes(value),
            "preview": redact_text(value[:80].decode("utf-8", "replace"), redact),
        }

    if isinstance(value, str):
        return redact_text(value, redact)

    if isinstance(value, tuple):
        return [normalize_value(item, redact) for item in value]

    if isinstance(value, list):
        return [normalize_value(item, redact) for item in value]

    if isinstance(value, set):
        return sorted(normalize_value(item, redact) for item in value)

    if isinstance(value, dict):
        return {
            redact_text(str(key), redact): normalize_value(item, redact)
            for key, item in value.items()
        }

    if isinstance(value, complex):
        return {"type": "complex", "real": value.real, "imag": value.imag}

    return value


def value_kind(value: Any) -> str:
    if isinstance(value, nuitka_blob.BlobDataValue):
        return "blob_data"
    if isinstance(value, nuitka_blob.BytesValue):
        return "bytes"
    if isinstance(value, dict) and "type" in value:
        return str(value["type"])
    if isinstance(value, tuple):
        return "tuple"
    if isinstance(value, list):
        return "list"
    if isinstance(value, str):
        return "str"
    if value is None:
        return "none"
    return type(value).__name__


def split_constant_blob(data: bytes) -> tuple[int, list[tuple[str, bytes]]]:
    errors = []

    for offset in nuitka_blob.candidate_blob_offsets(data):
        try:
            return offset, nuitka_blob.split_top_level_blob_from(data, offset)
        except nuitka_blob.BlobParseError as exc:
            errors.append(f"offset {offset}: {exc}")

    raise nuitka_blob.BlobParseError("; ".join(errors))


def parse_constant_blob(
    blob_path: Path,
    blob_format: str,
) -> tuple[bytes, int, list[tuple[str, bytes]], str, list[dict[str, Any]], list[dict[str, Any]]]:
    data = blob_path.read_bytes()
    section_offset, sections = split_constant_blob(data)
    chosen_format, parsed_sections, errors = nuitka_blob.parse_sections(sections, blob_format=blob_format)

    return data, section_offset, sections, chosen_format, parsed_sections, errors


def section_summary(section: dict[str, Any], redact: bool, include_values: bool) -> dict[str, Any]:
    result = {
        "name": section["name"],
        "size": section["size"],
        "format": section.get("format"),
        "count": section["count"],
        "trailing_bytes": section["trailing_bytes"],
        "strings": [redact_text(item, redact) for item in section["strings"]],
        "blob_data": [blob.as_summary() for blob in section["blob_values"]],
        "code_objects": normalize_value(section["code_objects"], redact),
    }

    values_key = "values" if include_values else "values_preview"
    values = section["values"] if include_values else section["values"][:20]
    result[values_key] = [normalize_value(item, redact) for item in values]
    return result


def write_blob_summary(
    blob_path: Path,
    output_dir: Path,
    data: bytes,
    section_offset: int,
    sections: list[tuple[str, bytes]],
    requested_blob_format: str,
    chosen_blob_format: str,
    parsed_sections: list[dict[str, Any]],
    parse_errors: list[dict[str, Any]],
    redact: bool,
) -> Path:
    parsed_by_index = {
        section["_top_level_index"]: section
        for section in parsed_sections
    }
    errors_by_index = {item["index"]: item for item in parse_errors}

    section_records = []
    for section_index, (name, section_data) in enumerate(sections):
        parsed = parsed_by_index.get(section_index)
        error = errors_by_index.get(section_index)
        record = {
            "index": section_index,
            "name": name,
            "size": len(section_data),
            "sha256": sha256_bytes(section_data),
            "head_hex": section_data[:32].hex(),
            "parsed": parsed is not None,
        }

        if parsed is not None:
            record.update(
                {
                    "format": parsed["format"],
                    "count": parsed["count"],
                    "trailing_bytes": parsed["trailing_bytes"],
                    "strings_count": len(parsed["strings"]),
                    "strings_preview": [redact_text(item, redact) for item in parsed["strings"][:40]],
                    "blob_data_count": len(parsed["blob_values"]),
                    "code_objects_count": len(parsed["code_objects"]),
                }
            )
        if error is not None:
            record["parse_error"] = error["error"]

        section_records.append(record)

    summary = {
        "blob_path": str(blob_path),
        "blob_size": len(data),
        "blob_sha256": sha256_bytes(data),
        "requested_blob_format": requested_blob_format,
        "chosen_blob_format": chosen_blob_format,
        "top_level_offset": section_offset,
        "prefix_hex": data[:section_offset].hex(),
        "section_count": len(sections),
        "parsed_section_count": len(parsed_sections),
        "parse_error_count": len(parse_errors),
        "sections": section_records,
        "parse_errors": parse_errors,
    }

    path = output_dir / "blob_summary.json"
    write_json(path, summary)
    return path


def export_section_files(parsed_sections: list[dict[str, Any]], output_dir: Path, redact: bool) -> list[dict[str, Any]]:
    modules_dir = output_dir / "modules"
    modules_dir.mkdir(parents=True, exist_ok=True)
    module_records = []

    for section in parsed_sections:
        module_name = section["name"] or "global"
        module_safe = safe_name(module_name, "global")
        text_path = modules_dir / f"{module_safe}.constants.txt"
        json_path = modules_dir / f"{module_safe}.constants.json"

        lines = [
            f"section: {module_name}",
            f"size: {section['size']}",
            f"constants: {section['count']}",
            f"strings: {len(section['strings'])}",
            f"blob_data: {len(section['blob_values'])}",
            f"code_objects: {len(section['code_objects'])}",
            "",
        ]

        if section["code_objects"]:
            lines.append("[code_objects]")
            for code_object in section["code_objects"]:
                lines.append(json.dumps(normalize_value(code_object, redact), ensure_ascii=False))
            lines.append("")

        lines.append("[constants]")
        constants_json = []
        for index, value in enumerate(section["values"]):
            normalized = normalize_value(value, redact)
            constants_json.append(
                {
                    "index": index,
                    "kind": value_kind(value),
                    "value": normalized,
                }
            )
            rendered = json.dumps(normalized, ensure_ascii=False)
            lines.append(f"{index:04d} {value_kind(value):<16} {rendered}")

        write_text(text_path, "\n".join(lines) + "\n")
        write_json(json_path, constants_json)

        module_records.append(
            {
                "name": module_name,
                "constants": section["count"],
                "strings": len(section["strings"]),
                "blob_data": len(section["blob_values"]),
                "code_objects": normalize_value(section["code_objects"], redact),
                "constants_txt": str(text_path),
                "constants_json": str(json_path),
            }
        )

    return module_records


def write_pyc_from_marshal(path: Path, marshalled_code: bytes) -> None:
    header = importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, 0, 0)
    write_bytes(path, header + marshalled_code)


def pyarmor_runtime_name(data: bytes) -> str | None:
    match = re.match(rb"PY([0-9A-Za-z_]+)\x00", data[:32])
    if match is None:
        return None

    suffix = match.group(1).decode("ascii", "ignore")
    if not suffix:
        return None

    return f"pyarmor_runtime_{suffix}"


def bytes_literal_lines(data: bytes, indent: str = "    ", chunk_size: int = 64) -> list[str]:
    return [f"{indent}{data[index:index + chunk_size]!r}" for index in range(0, len(data), chunk_size)]


def write_pyarmor_wrapper(path: Path, runtime_name: str, payload: bytes) -> None:
    lines = [
        f"from {runtime_name} import __pyarmor__",
        f"__pyarmor__(__name__, __file__, {payload!r})",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text(path, "\n".join(lines))


def export_blobdata(parsed_sections: list[dict[str, Any]], output_dir: Path) -> list[dict[str, Any]]:
    blobdata_dir = output_dir / "blobdata"
    bytecode_dir = output_dir / "bytecode"
    records = []

    for section in parsed_sections:
        module_safe = safe_name(section["name"] or "global", "global")

        for index, blob_value in enumerate(section["blob_values"]):
            raw_suffix = ".marshal" if blob_value.code_summary is not None else ".bin"
            raw_path = blobdata_dir / f"{module_safe}_{index:04d}{raw_suffix}"
            write_bytes(raw_path, blob_value.data)

            record = {
                "section": section["name"],
                "index": index,
                "size": len(blob_value.data),
                "sha256": sha256_bytes(blob_value.data),
                "raw_path": str(raw_path),
                "marshal_code": blob_value.code_summary,
            }

            try:
                code = marshal.loads(blob_value.data)
            except Exception as exc:
                record["marshal_error"] = str(exc)
            else:
                if hasattr(code, "co_name"):
                    pyc_name = f"{module_safe}_{index:04d}_{safe_name(code.co_name, 'code')}.pyc"
                    pyc_path = bytecode_dir / pyc_name
                    write_pyc_from_marshal(pyc_path, blob_value.data)
                    record["pyc_path"] = str(pyc_path)
                    record["code"] = {
                        "co_name": code.co_name,
                        "co_filename": code.co_filename,
                        "co_firstlineno": code.co_firstlineno,
                        "co_argcount": code.co_argcount,
                        "co_names": list(code.co_names),
                        "co_consts_count": len(code.co_consts),
                    }

            records.append(record)

    write_json(output_dir / "blobdata_manifest.json", records)
    return records


def export_bytes_constants(parsed_sections: list[dict[str, Any]], output_dir: Path) -> list[dict[str, Any]]:
    bytes_dir = output_dir / "bytes_constants"
    pyarmor_dir = output_dir / "pyarmor_wrappers"
    records = []

    for section in parsed_sections:
        module_safe = safe_name(section["name"] or "global", "global")

        for const_index, value in enumerate(section["values"]):
            if not isinstance(value, nuitka_blob.BytesValue):
                continue

            data = value.data
            raw_path = bytes_dir / f"{module_safe}_{const_index:04d}.bin"
            write_bytes(raw_path, data)

            record = {
                "section": section["name"],
                "index": const_index,
                "size": len(data),
                "sha256": sha256_bytes(data),
                "raw_path": str(raw_path),
            }

            runtime_name = pyarmor_runtime_name(data)
            if runtime_name is not None:
                wrapper_path = pyarmor_dir / f"{module_safe}_{const_index:04d}_pyarmor.py"
                write_pyarmor_wrapper(wrapper_path, runtime_name, data)
                record["pyarmor"] = True
                record["runtime_name"] = runtime_name
                record["wrapper_path"] = str(wrapper_path)
            else:
                record["pyarmor"] = False

            records.append(record)

    write_json(output_dir / "bytes_constants_manifest.json", records)
    return records


def make_payload_manifest(entries: list[tuple[str, bytes, int | None]]) -> list[dict[str, Any]]:
    manifest = []

    for filename, file_data, checksum in entries:
        is_pe = file_data.startswith(b"MZ")
        has_constant_blob = False
        lang_id = None
        blob_method = None

        if is_pe:
            try:
                pe = nuitka_dump._load_pe(data=file_data)
                resolved = nuitka_dump.resolve_constant_blob_from_pe(pe)
            except pefile.PEFormatError:
                resolved = None

            if resolved is not None:
                has_constant_blob = True
                _blob, lang_id, blob_method = resolved

        manifest.append(
            {
                "name": filename,
                "size": len(file_data),
                "sha256": sha256_bytes(file_data),
                "checksum": checksum,
                "is_pe": is_pe,
                "has_constant_blob": has_constant_blob,
                "constant_blob_method": blob_method,
                "constant_blob_lang_id": lang_id,
            }
        )

    return manifest


def copy_input_backend(input_path: Path, output_dir: Path) -> Path:
    backend_dir = output_dir / "backend"
    backend_dir.mkdir(parents=True, exist_ok=True)
    copied_path = backend_dir / input_path.name

    if input_path.resolve() != copied_path.resolve():
        shutil.copy2(input_path, copied_path)

    return copied_path


def export_direct_backend(input_path: Path, output_dir: Path) -> tuple[Path | None, list[dict[str, Any]]]:
    resolved = nuitka_dump.resolve_constant_blob(input_path)
    if resolved is None:
        return None, []

    blob, lang_id, method = resolved
    backend_path = copy_input_backend(input_path, output_dir)
    blob_path = output_dir / "blobs" / "constant_blob_id3.bin"
    write_bytes(blob_path, blob)

    return blob_path, [
        {
            "source": "input",
            "name": input_path.name,
            "path": str(input_path),
            "copied_path": str(backend_path),
            "constant_blob": str(blob_path),
            "constant_blob_size": len(blob),
            "constant_blob_sha256": sha256_bytes(blob),
            "constant_blob_method": method,
            "lang_id": lang_id,
        }
    ]


def export_onefile(input_path: Path, output_dir: Path, checksum_mode: str) -> tuple[Path | None, list[dict[str, Any]], list[dict[str, Any]]]:
    payload_blob = nuitka_dump.locate_onefile_payload(input_path)
    if payload_blob is None:
        return None, [], []

    payload_lang_id = None
    payload_dir = output_dir / "payload"
    raw_payload_path = payload_dir / "resource_id27.bin"
    write_bytes(raw_payload_path, payload_blob)

    payload_region = nuitka_dump.get_onefile_payload_region(payload_blob)
    payload_data = nuitka_dump.decompress_onefile_body(payload_region)
    entries, used_checksums = nuitka_dump.parse_payload_entries_auto(payload_data, checksum_mode)

    extracted_dir = payload_dir / "extracted"
    extracted_paths = nuitka_dump.extract_entries(entries, extracted_dir)
    extracted_by_name = {
        filename: str(path)
        for (filename, _file_data, _checksum), path in zip(entries, extracted_paths)
    }

    manifest = make_payload_manifest(entries)
    for item in manifest:
        item["extracted_path"] = extracted_by_name.get(item["name"])

    payload_report = {
        "raw_payload_path": str(raw_payload_path),
        "raw_payload_size": len(payload_blob),
        "raw_payload_sha256": sha256_bytes(payload_blob),
        "lang_id": payload_lang_id,
        "header": payload_blob[:3].decode("ascii", "replace"),
        "decompressed_size": len(payload_data),
        "entry_count": len(entries),
        "used_checksums": used_checksums,
        "extract_dir": str(extracted_dir),
    }
    write_json(payload_dir / "payload_info.json", payload_report)
    write_json(payload_dir / "payload_manifest.json", manifest)

    backend_records = []
    primary_blob_path = None

    for index, (filename, file_data, _checksum) in enumerate(entries):
        if not file_data.startswith(b"MZ"):
            continue

        try:
            pe = nuitka_dump._load_pe(data=file_data)
        except pefile.PEFormatError:
            continue

        resolved = nuitka_dump.resolve_constant_blob_from_pe(pe)
        if resolved is None:
            continue

        blob, lang_id, method = resolved
        backend_safe = safe_name(Path(filename).name or f"backend_{index}", f"backend_{index}")
        blob_path = output_dir / "blobs" / f"{backend_safe}_constant_blob_id3.bin"
        write_bytes(blob_path, blob)

        if primary_blob_path is None:
            primary_blob_path = output_dir / "blobs" / "constant_blob_id3.bin"
            write_bytes(primary_blob_path, blob)

        backend_records.append(
            {
                "source": "onefile_payload",
                "name": filename,
                "extracted_path": extracted_by_name.get(filename),
                "constant_blob": str(blob_path),
                "constant_blob_size": len(blob),
                "constant_blob_sha256": sha256_bytes(blob),
                "constant_blob_method": method,
                "lang_id": lang_id,
            }
        )

    return primary_blob_path, backend_records, [payload_report]


def export_constants(
    blob_path: Path,
    output_dir: Path,
    redact: bool,
    blob_format: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], Path, str]:
    data, section_offset, sections, chosen_blob_format, parsed_sections, parse_errors = parse_constant_blob(blob_path, blob_format)
    blob_summary_path = write_blob_summary(
        blob_path=blob_path,
        output_dir=output_dir,
        data=data,
        section_offset=section_offset,
        sections=sections,
        requested_blob_format=blob_format,
        chosen_blob_format=chosen_blob_format,
        parsed_sections=parsed_sections,
        parse_errors=parse_errors,
        redact=redact,
    )

    full_summary = [
        section_summary(section, redact=redact, include_values=True)
        for section in parsed_sections
    ]
    preview_summary = [
        section_summary(section, redact=redact, include_values=False)
        for section in parsed_sections
    ]

    write_json(output_dir / "constants_full.json", full_summary)
    write_json(output_dir / "constants_preview.json", preview_summary)

    module_records = export_section_files(parsed_sections, output_dir, redact)
    blobdata_records = export_blobdata(parsed_sections, output_dir)
    bytes_records = export_bytes_constants(parsed_sections, output_dir)

    code_objects = []
    for section in parsed_sections:
        for code_object in section["code_objects"]:
            item = normalize_value(code_object, redact)
            item["section"] = section["name"]
            code_objects.append(item)

    write_json(output_dir / "code_objects.json", code_objects)

    strings_index = []
    for section in parsed_sections:
        unique_strings = []
        seen = set()
        for string in section["strings"]:
            redacted = redact_text(string, redact)
            if redacted in seen:
                continue
            seen.add(redacted)
            unique_strings.append(redacted)
        strings_index.append({"section": section["name"], "strings": unique_strings})
    write_json(output_dir / "strings_by_section.json", strings_index)

    write_json(output_dir / "parse_errors.json", parse_errors)

    return module_records, blobdata_records, bytes_records, parse_errors, blob_summary_path, chosen_blob_format


def write_ida_helper_script(output_dir: Path) -> Path:
    script_path = output_dir / "ida" / "ida_nuitka_helper.py"
    constants_json = output_dir / "constants_full.json"
    output_json = output_dir / "ida" / "ida_nuitka_string_xrefs.json"

    content = f'''# Generated by nuitka_auto_export.py
# Run this inside IDA after loading the backend EXE/DLL.

import json
import os

import idaapi
import idautils
import idc

CONSTANTS_JSON = {str(constants_json)!r}
OUTPUT_JSON = {str(output_json)!r}
APPLY_COMMENTS = False
MAX_INTERESTING_STRINGS = 20000


def walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from walk_strings(key)
            yield from walk_strings(item)


def load_interesting_strings():
    with open(CONSTANTS_JSON, "r", encoding="utf-8") as handle:
        sections = json.load(handle)

    names = set()
    preferred = set()

    for section in sections:
        section_name = section.get("name") or ""
        if section_name:
            preferred.add(section_name)

        for code_object in section.get("code_objects", []):
            for key in ("name", "qualname_owner"):
                value = code_object.get(key)
                if isinstance(value, str) and value:
                    preferred.add(value)

        for string in section.get("strings", []):
            if isinstance(string, str) and len(string) >= 3:
                names.add(string)

        for value in section.get("values", []):
            for string in walk_strings(value):
                if len(string) >= 3:
                    names.add(string)

    interesting = list(preferred) + sorted(names - preferred)
    return set(interesting[:MAX_INTERESTING_STRINGS])


def main():
    interesting = load_interesting_strings()
    strings = idautils.Strings()

    try:
        strings.setup(ignore_instructions=True, display_only_existing_strings=True)
    except TypeError:
        try:
            strings.setup()
        except Exception:
            pass

    hits = []

    for item in strings:
        text = str(item)
        if text not in interesting:
            continue

        refs = []
        funcs = set()

        for xref in idautils.XrefsTo(item.ea):
            refs.append(hex(xref.frm))
            func = idaapi.get_func(xref.frm)
            if func:
                funcs.add(hex(func.start_ea))
            if APPLY_COMMENTS:
                idc.set_cmt(xref.frm, "Nuitka const string: " + text[:200], 0)

        hits.append(
            {{
                "string": text,
                "ea": hex(item.ea),
                "refs": refs,
                "functions": sorted(funcs),
            }}
        )

    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as handle:
        json.dump(hits, handle, indent=2, ensure_ascii=False)

    print("Nuitka helper complete")
    print("Interesting strings:", len(interesting))
    print("String hits:", len(hits))
    print("Output:", OUTPUT_JSON)


if __name__ == "__main__":
    main()
'''

    script_path.parent.mkdir(parents=True, exist_ok=True)
    write_text(script_path, content)
    return script_path


def write_ai_context(
    output_dir: Path,
    input_path: Path,
    mode: str,
    backend_records: list[dict[str, Any]],
    module_records: list[dict[str, Any]],
    blobdata_records: list[dict[str, Any]],
    bytes_records: list[dict[str, Any]],
    parse_errors: list[dict[str, Any]],
    blob_summary_path: Path,
    ida_helper_path: Path,
) -> Path:
    path = output_dir / "ai_context.md"

    backend_lines = []
    for record in backend_records:
        backend_path = record.get("copied_path") or record.get("extracted_path") or record.get("path")
        backend_lines.append(f"- {record['name']} -> {backend_path}")

    module_lines = []
    for record in module_records:
        module_lines.append(
            f"- {record['name']}: constants={record['constants']}, "
            f"strings={record['strings']}, code_objects={len(record['code_objects'])}, "
            f"file={record['constants_txt']}"
        )

    pyc_lines = []
    for record in blobdata_records:
        if record.get("pyc_path"):
            pyc_lines.append(f"- {record['section']}[{record['index']}] -> {record['pyc_path']}")

    pyarmor_lines = []
    for record in bytes_records:
        if record.get("pyarmor"):
            pyarmor_lines.append(
                f"- {record['section']}[{record['index']}] runtime={record['runtime_name']} wrapper={record['wrapper_path']}"
            )

    lines = [
        """
1. Do not infer functionality from strings alone.
   - Strings, symbol names, imports, filenames, log messages, error messages, URLs, and class names are only weak hints.
   - Never treat a string as proof that a feature or code path exists.
   - A string may be unused, dead code, obfuscated, misleading, shared by another component, or included by a third-party library.

2. Every conclusion must be supported by code-level evidence obtained from reverse-engineering tools such as:
   - IDA Pro
   - Hex-Rays Decompiler
   - Ghidra
   - Binary Ninja
   - Hopper
   - radare2 / Cutter
   - WinDbg, x64dbg, GDB, LLDB
   - Frida or other runtime instrumentation tools

3. Analyze the real execution flow by examining:
   - Function boundaries
   - Cross-references
   - Callers and callees
   - Control-flow graphs
   - Call graphs
   - Data-flow and variable usage
   - Function arguments and return values
   - Global variables and structure fields
   - Virtual function tables
   - Interface implementations
   - Imported and dynamically resolved APIs
   - Indirect calls and function pointers
   - Switch tables
   - Exception handling paths
   - Object construction and destruction
   - Memory allocation and ownership
   - File, registry, network, database, IPC, and cryptographic operations

4. For every reconstructed feature, provide an evidence chain:

   Entry point
   → caller
   → validation logic
   → main processing function
   → state changes
   → external side effects
   → return value or output

5. Before naming a function, determine its behavior from:
   - Inputs
   - Outputs
   - Side effects
   - APIs it calls
   - Fields it reads or writes
   - Conditions controlling its execution
   - Relationship with surrounding functions

6. Do not rename a function merely because it references a suggestive string.
   For example, a function referencing "login", "encrypt", "upload", or "success" must not automatically be named Login, Encrypt, Upload, or VerifySuccess.

7. Distinguish clearly between:
   - Confirmed behavior
   - Strong inference
   - Weak hypothesis
   - Unknown behavior

8. Use confidence labels:
   - Confirmed: directly demonstrated by instructions, data flow, or runtime behavior
   - High confidence: supported by multiple independent code-level indicators
   - Medium confidence: plausible but missing one important part of the execution path
   - Low confidence: based mainly on naming, strings, or incomplete evidence

9. If the available evidence is insufficient, do not guess.
   Instead, state exactly what must be inspected next, such as:
   - Xrefs to a global variable
   - Caller of an indirect function
   - Runtime register values
   - Heap object layout
   - Vtable entries
   - Network buffer contents
   - Decryption result
   - Dynamic API resolution
   - A specific breakpoint or Frida hook

10. Treat decompiler output as an approximation, not as original source code.
    Validate suspicious decompiler output against the assembly when:
    - Types appear incorrect
    - Variables are reused strangely
    - Control flow is simplified
    - Signed and unsigned comparisons are unclear
    - Pointer arithmetic is involved
    - SIMD instructions are present
    - Exception handling affects execution
    - Indirect branches or jump tables are used

11. Reconstruct data structures based on access patterns.
    Document:
    - Field offsets
    - Estimated field types
    - Read/write locations
    - Object size
    - Constructor behavior
    - Relationships with other structures

12. When reconstructing a high-level function, do not invent missing implementation details.
    Produce pseudocode only for behavior supported by evidence."""
        "# Nuitka static analysis export",
        "",
        f"Input: `{input_path}`",
        f"Mode: `{mode}`",
        "",
        "## Backend files to load in IDA",
        *(backend_lines or ["- No backend PE with RT_RCDATA ID 3 was found."]),
        "",
        "## Main artifacts",
        f"- Blob summary JSON: `{blob_summary_path}`",
        f"- Full constants JSON: `{output_dir / 'constants_full.json'}`",
        f"- Preview constants JSON: `{output_dir / 'constants_preview.json'}`",
        f"- Per-module constants: `{output_dir / 'modules'}`",
        f"- Strings by section: `{output_dir / 'strings_by_section.json'}`",
        f"- Code objects: `{output_dir / 'code_objects.json'}`",
        f"- BlobData manifest: `{output_dir / 'blobdata_manifest.json'}`",
        f"- Bytes constants manifest: `{output_dir / 'bytes_constants_manifest.json'}`",
        f"- IDA helper script: `{ida_helper_path}`",
        "",
        "## Modules / sections",
        *(module_lines or ["- No parsed sections."]),
        "",
        "## Marshal / .pyc candidates",
        *(pyc_lines or ["- No marshal code objects were exported as .pyc."]),
        "",
        "## PyArmor byte wrappers",
        *(pyarmor_lines or ["- No PyArmor-looking bytes constants were exported as wrappers."]),
        "",
        "## IDA workflow",
        "1. Open the backend PE listed above in IDA and wait for auto-analysis to finish.",
        "2. Run `ida/ida_nuitka_helper.py` inside IDA.",
        "3. Use `ida/ida_nuitka_string_xrefs.json` with the constants files to map native functions to module constants.",
        "4. Use the annotated strings, constants, and decompile output for AI-assisted reconstruction.",
        "",
        "## AI mental model prompt for Nuitka",
        "Use the following context as a working mental model when another AI system needs to reason about Nuitka artifacts without prior Nuitka-specific knowledge:",
        "",
        "- Treat Nuitka as a Python compiler, not merely a packer. It analyzes Python source, builds an internal representation, generates C/C++ code compatible with CPython semantics, and relies on the system compiler to produce an executable or extension module.",
        "- Keep the pipeline in mind: source -> analysis -> code generation -> native build -> packaging/distribution -> runtime bootstrap -> embedded constants/resources.",
        "- Distinguish packaging modes: accelerated mode uses an existing Python environment; standalone mode bundles the runtime and dependencies; onefile mode wraps the standalone payload inside an outer launcher; module mode produces an extension module.",
        "- In onefile mode on Windows, the outer executable may contain a payload resource such as RT_RCDATA ID 27. Extracting that payload can reveal the real backend PE and bundled dependencies.",
        "- The backend PE may contain a Nuitka constant blob in RT_RCDATA ID 3. That blob is a serialized runtime data structure used to materialize constants when the program starts.",
        "- The constant blob is organized into named sections. Each section contains a count, a stream of tagged values, and an end marker. Parsing requires choosing the correct stream format, typically fixed/newer or legacy/older.",
        "- Tagged values can represent strings, bytes, tuples, lists, dicts, sets, integers, large integers, floats, complex numbers, slices, ranges, builtins, generic aliases, union types, BlobData records, and code object metadata.",
        "- Nuitka string data is important: strings may be stored as empty, single-byte, zero-terminated UTF-8, length-prefixed UTF-8, or attribute-name variants. Upstream Nuitka uses UTF-8 with surrogatepass semantics, so lone surrogates may be valid according to Nuitka even if strict UTF-8 output code would choke on them.",
        "- BlobData is not automatically equivalent to Python source. It may be raw binary payload, marshal-serialized code-related data, or other runtime material. Some BlobData records can be tested with marshal.loads and written as .pyc candidates, but that is only a heuristic for reverse engineering.",
        "- Code object metadata inside the blob can expose names, line numbers, argument counts, variable names, free vars, qualname ownership, and code kind flags. These artifacts help reconstruct program structure even when full source recovery is impossible.",
        "- For reverse engineering, separate the layers explicitly: outer onefile launcher, extracted payload, backend PE, PE resources, constant blob, per-section constants, BlobData, code object metadata, and string cross-references in IDA/Ghidra.",
        "- Do not confuse Nuitka with PyInstaller. Nuitka compiles program logic into native code and then packages runtime artifacts around that compiled result; PyInstaller primarily bundles the interpreter, bytecode, and dependencies.",
        "- Treat version and platform details as version-dependent unless confirmed from source. Blob tags, formats, section parsing behavior, payload handling, and resource layouts can drift between Nuitka versions and Python versions.",
        "- When analyzing any Nuitka-related component, answer four questions: what is it, at which stage does it appear, what is it used for, and how does it connect to compile-time generation, runtime bootstrap, packaging, and reverse engineering.",
        "",
        "## Parse errors",
        *(f"- {item['section']}: {item['error']}" for item in parse_errors),
    ]

    write_text(path, "\n".join(lines) + "\n")
    return path


def write_report(
    output_dir: Path,
    input_path: Path,
    mode: str,
    backend_records: list[dict[str, Any]],
    payload_reports: list[dict[str, Any]],
    module_records: list[dict[str, Any]],
    blobdata_records: list[dict[str, Any]],
    bytes_records: list[dict[str, Any]],
    parse_errors: list[dict[str, Any]],
    requested_blob_format: str,
    chosen_blob_format: str,
    blob_summary_path: Path,
    ida_helper_path: Path,
    ai_context_path: Path,
) -> None:
    report = {
        "input": str(input_path),
        "mode": mode,
        "backend_records": backend_records,
        "payload_reports": payload_reports,
        "module_count": len(module_records),
        "modules": module_records,
        "blobdata_count": len(blobdata_records),
        "bytes_constants_count": len(bytes_records),
        "pyarmor_wrappers_count": sum(1 for record in bytes_records if record.get("pyarmor")),
        "bytes_constants": bytes_records,
        "pyc_count": sum(1 for record in blobdata_records if record.get("pyc_path")),
        "parse_errors": parse_errors,
        "requested_blob_format": requested_blob_format,
        "chosen_blob_format": chosen_blob_format,
        "blob_summary": str(blob_summary_path),
        "ida_helper": str(ida_helper_path),
        "ai_context": str(ai_context_path),
    }
    write_json(output_dir / "export_manifest.json", report)


def export_all(args: argparse.Namespace) -> None:
    input_path = args.input.resolve()
    output_dir = args.output.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    mode = "backend"
    payload_reports: list[dict[str, Any]] = []

    blob_path = None
    backend_records: list[dict[str, Any]] = []

    if not args.onefile_only:
        blob_path, backend_records = export_direct_backend(input_path, output_dir)

    if blob_path is None:
        mode = "onefile"
        blob_path, backend_records, payload_reports = export_onefile(
            input_path=input_path,
            output_dir=output_dir,
            checksum_mode=args.checksums,
        )

    if blob_path is None:
        raise RuntimeError(
            "No Nuitka constant blob found. The file may not be a Nuitka backend, "
            "or the onefile payload/resource mode is unsupported."
        )

    module_records, blobdata_records, bytes_records, parse_errors, blob_summary_path, chosen_blob_format = export_constants(
        blob_path=blob_path,
        output_dir=output_dir,
        redact=not args.no_redact,
        blob_format=args.blob_format,
    )

    ida_helper_path = write_ida_helper_script(output_dir)
    ai_context_path = write_ai_context(
        output_dir=output_dir,
        input_path=input_path,
        mode=mode,
        backend_records=backend_records,
        module_records=module_records,
        blobdata_records=blobdata_records,
        bytes_records=bytes_records,
        parse_errors=parse_errors,
        blob_summary_path=blob_summary_path,
        ida_helper_path=ida_helper_path,
    )
    write_report(
        output_dir=output_dir,
        input_path=input_path,
        mode=mode,
        backend_records=backend_records,
        payload_reports=payload_reports,
        module_records=module_records,
        blobdata_records=blobdata_records,
        bytes_records=bytes_records,
        parse_errors=parse_errors,
        requested_blob_format=args.blob_format,
        chosen_blob_format=chosen_blob_format,
        blob_summary_path=blob_summary_path,
        ida_helper_path=ida_helper_path,
        ai_context_path=ai_context_path,
    )

    print(f"Input       : {input_path}")
    print(f"Output      : {output_dir}")
    print(f"Mode        : {mode}")
    print(f"Blob format : {chosen_blob_format}")
    print(f"Backends    : {len(backend_records)}")
    print(f"Modules     : {len(module_records)}")
    print(f"BlobData    : {len(blobdata_records)}")
    print(f"Bytes const : {len(bytes_records)}")
    print(f"PyArmor py  : {sum(1 for record in bytes_records if record.get('pyarmor'))}")
    print(f"PYC files   : {sum(1 for record in blobdata_records if record.get('pyc_path'))}")
    print(f"Blob summary: {blob_summary_path}")
    print(f"IDA helper  : {ida_helper_path}")
    print(f"AI context  : {ai_context_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automate Nuitka onefile/backend export for static reversing."
    )
    parser.add_argument("input", type=Path, help="Nuitka backend EXE/DLL or outer onefile EXE")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output directory. Default: <input>_nuitka_export",
    )
    parser.add_argument(
        "--checksums",
        choices=("auto", "yes", "no"),
        default="auto",
        help="Whether onefile payload entries contain CRC32 checksums.",
    )
    parser.add_argument(
        "--onefile-only",
        action="store_true",
        help="Skip direct backend probing and force RT_RCDATA ID 27 extraction.",
    )
    parser.add_argument(
        "--blob-format",
        "--blob-version",
        choices=("auto", "fixed", "legacy"),
        default="auto",
        help="Nuitka constants stream format: auto, fixed/newer, or legacy/older.",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Do not redact Token/Bearer values in exported JSON/text summaries.",
    )

    args = parser.parse_args()
    if args.output is None:
        args.output = args.input.with_name(args.input.stem + "_nuitka_export")

    try:
        export_all(args)
    except (RuntimeError, nuitka_dump.ExtractionError, pefile.PEFormatError, nuitka_blob.BlobParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
