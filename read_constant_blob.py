#!/usr/bin/env python3
import argparse
import hashlib
import json
import marshal
import math
import struct
from pathlib import Path


TAGS = {
    "previous": 0x70,  # p
    "none": 0x6E,  # n
    "true": 0x74,  # t
    "false": 0x46,  # F
    "tuple": 0x54,  # T + int32 count
    "list": 0x4C,  # L + int32 count
    "dict": 0x44,  # D + int32 count, keys then values
    "set": 0x53,  # S + int32 count
    "frozenset": 0x50,  # P + int32 count
    "long_positive_small": 0x6C,  # l + uint32
    "long_signed": 0x71,  # q + int64
    "long_large": 0x67,  # g + sign byte + int32 qword count + uint64 parts
    "int_positive": 0x69,
    "int_negative": 0x49,
    "float_special": 0x5A,  # Z + selector
    "float": 0x66,  # f + double
    "text_empty": 0x73,
    "text_single": 0x77,  # w + one byte
    "text_utf8_length_prefixed": 0x76,  # v + int32 length
    "text_utf8_zero_terminated": 0x75,  # u + NUL-terminated UTF-8
    "attribute_name": 0x61,  # a + NUL-terminated interned UTF-8
    "bytes_length_prefixed": 0x62,  # b + int32 length
    "bytes_zero_terminated": 0x63,  # c + NUL-terminated bytes
    "bytes_single": 0x64,  # d + one byte
    "slice": 0x3A,
    "range": 0x3B,
    "complex_special": 0x4A,
    "complex": 0x6A,
    "bytearray": 0x42,  # B + int32 length
    "builtin_anon": 0x4D,
    "builtin_special": 0x51,
    "blob_data": 0x58,  # X + int32 length
    "generic_alias": 0x47,  # G + origin + args
    "generic_alias_legacy": 0x41,
    "union_type": 0x48,
    "builtin_named": 0x4F,
    "builtin_exception": 0x45,
    "code_object": 0x43,
    "end": 0x2E,
}

TAG_NAMES = {value: name for name, value in TAGS.items()}

CODE_FLAG_QUALNAME = 0x0000000000000001
CODE_FLAG_FREE_VARS = 0x0000000000000002
CODE_FLAG_KW_ONLY = 0x0000000000000004
CODE_FLAG_POS_ONLY = 0x0000000000000008
CODE_KIND_MASK = 0x0000000000000030
CODE_KIND_GENERATOR = 0x0000000000000010
CODE_KIND_COROUTINE = 0x0000000000000020
CODE_KIND_ASYNCGEN = 0x0000000000000030
CODE_FLAG_OPTIMIZED = 0x0000000000000040
CODE_FLAG_NEWLOCALS = 0x0000000000000080
CODE_FLAG_VARARGS = 0x0000000000000100
CODE_FLAG_VARKEYWORDS = 0x0000000000000200


class BlobParseError(RuntimeError):
    pass


class BytesValue:
    def __init__(self, data):
        self.data = data

    def as_summary(self):
        return {
            "type": "bytes",
            "size": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "preview": bytes_preview(self.data),
        }


class BlobDataValue:
    def __init__(self, data):
        self.data = data
        self.code_summary = try_marshal_code_summary(data)

    def as_summary(self):
        result = {
            "type": "blob_data",
            "size": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "head_hex": self.data[:32].hex(),
        }

        if self.code_summary is not None:
            result["marshal_code"] = self.code_summary

        return result


class Reader:
    def __init__(self, data, section_name, blob_format="fixed"):
        self.data = data
        self.section_name = section_name
        self.blob_format = blob_format
        self.offset = 0
        self.last_value = None
        self.strings = []
        self.bytes_values = []
        self.blob_values = []
        self.code_objects = []

    def remaining(self):
        return len(self.data) - self.offset

    def read(self, size):
        if self.offset + size > len(self.data):
            raise BlobParseError(
                f"section {self.section_name!r}: need {size} bytes at offset {self.offset}, "
                f"only {self.remaining()} remain"
            )

        result = self.data[self.offset : self.offset + size]
        self.offset += size
        return result

    def peek_byte(self):
        if self.offset >= len(self.data):
            raise BlobParseError(f"section {self.section_name!r}: unexpected EOF")
        return self.data[self.offset]

    def read_byte(self):
        return self.read(1)[0]

    def read_u32(self):
        return struct.unpack("<I", self.read(4))[0]

    def read_i32(self):
        return struct.unpack("<i", self.read(4))[0]

    def read_i64(self):
        return struct.unpack("<q", self.read(8))[0]

    def read_u64(self):
        return struct.unpack("<Q", self.read(8))[0]

    def read_count32(self):
        count = self.read_i32()
        if count < 0:
            raise BlobParseError(
                f"section {self.section_name!r}: negative item count {count} at offset {self.offset - 4}"
            )
        return count

    def read_size32(self):
        size = self.read_i32()
        if size < 0:
            raise BlobParseError(
                f"section {self.section_name!r}: negative byte size {size} at offset {self.offset - 4}"
            )
        return size

    def read_count(self):
        if self.blob_format == "legacy":
            return self.read_varint()
        return self.read_count32()

    def read_size(self):
        if self.blob_format == "legacy":
            return self.read_varint()
        return self.read_size32()

    def read_varint(self):
        result = 0
        shift = 0

        while True:
            byte = self.read_byte()
            result |= (byte & 0x7F) << shift

            if byte < 128:
                return result

            shift += 7
            if shift > 70:
                raise BlobParseError("variable-length integer is too large")

    def read_zbytes(self):
        end = self.data.find(b"\0", self.offset)
        if end < 0:
            raise BlobParseError(f"section {self.section_name!r}: unterminated zero string")

        result = self.data[self.offset:end]
        self.offset = end + 1
        return result

    def decode_text(self, data, *, description):
        try:
            return data.decode("utf-8", "surrogatepass")
        except UnicodeDecodeError as exc:
            raise BlobParseError(
                f"section {self.section_name!r}: invalid UTF-8 in {description} at offset {self.offset - len(data)}"
            ) from exc

    def read_text_z(self):
        data = self.read_zbytes()
        text = self.decode_text(data, description="zero-terminated string")
        self.strings.append(text)
        return text

    def read_text_len(self):
        size = self.read_size()
        data = self.read(size)
        text = self.decode_text(data, description=f"length-prefixed string ({size} bytes)")
        self.strings.append(text)
        return text

    def parse_value(self):
        tag = self.read_byte()

        if tag == TAGS["previous"]:
            value = self.last_value
        elif tag == TAGS["none"]:
            value = None
        elif tag == TAGS["true"]:
            value = True
        elif tag == TAGS["false"]:
            value = False
        elif tag == TAGS["tuple"]:
            value = tuple(self.parse_sequence_items(self.read_count()))
        elif tag == TAGS["list"]:
            value = list(self.parse_sequence_items(self.read_count()))
        elif tag == TAGS["dict"]:
            value = self.parse_dict(self.read_count())
        elif tag == TAGS["set"]:
            value = {repr(item) for item in self.parse_sequence_items(self.read_count())}
        elif tag == TAGS["frozenset"]:
            value = {"type": "frozenset", "items": self.parse_sequence_items(self.read_count())}
        elif tag == TAGS["long_positive_small"]:
            value = self.read_varint() if self.blob_format == "legacy" else self.read_u32()
        elif tag == TAGS["long_signed"]:
            value = -self.read_varint() if self.blob_format == "legacy" else self.read_i64()
        elif tag == TAGS["long_large"]:
            value = self.parse_large_int(sign=1 if self.blob_format == "legacy" else None)
        elif tag == TAGS["generic_alias"] and self.blob_format == "legacy":
            value = self.parse_large_int(sign=-1)
        elif tag == TAGS["int_positive"]:
            value = self.read_varint()
        elif tag == TAGS["int_negative"]:
            value = -self.read_varint()
        elif tag == TAGS["float_special"]:
            value = self.parse_special_float()
        elif tag == TAGS["float"]:
            value = struct.unpack("<d", self.read(8))[0]
        elif tag == TAGS["text_empty"]:
            value = ""
            self.strings.append(value)
        elif tag == TAGS["text_single"]:
            value = self.read(1).decode("utf-8", "surrogatepass")
            self.strings.append(value)
        elif tag == TAGS["text_utf8_length_prefixed"]:
            value = self.read_text_len()
        elif tag in (TAGS["text_utf8_zero_terminated"], TAGS["attribute_name"]):
            value = self.read_text_z()
        elif tag == TAGS["bytes_length_prefixed"]:
            value = self.parse_bytes_value(self.read_size())
        elif tag == TAGS["bytes_zero_terminated"]:
            value = self.parse_bytes_value(None)
        elif tag == TAGS["bytes_single"]:
            value = self.parse_bytes_value(1)
        elif tag == TAGS["slice"]:
            self.last_value = None
            value = {"type": "slice", "start": self.parse_value(), "stop": self.parse_value(), "step": self.parse_value()}
        elif tag == TAGS["range"]:
            self.last_value = None
            value = {"type": "range", "start": self.parse_value(), "stop": self.parse_value(), "step": self.parse_value()}
        elif tag == TAGS["complex_special"]:
            self.last_value = None
            value = complex(self.parse_value(), self.parse_value())
        elif tag == TAGS["complex"]:
            real, imag = struct.unpack("<dd", self.read(16))
            value = complex(real, imag)
        elif tag == TAGS["bytearray"]:
            value = {"type": "bytearray", "data": self.parse_bytes_value(self.read_size())}
        elif tag == TAGS["builtin_anon"]:
            value = {"type": "builtin_anon", "stream_value": self.read_byte()}
        elif tag == TAGS["builtin_special"]:
            value = {"type": "builtin_special", "stream_value": self.read_byte()}
        elif tag == TAGS["blob_data"]:
            value = BlobDataValue(self.read(self.read_size()))
            self.blob_values.append(value)
        elif tag in (TAGS["generic_alias"], TAGS["generic_alias_legacy"]):
            self.last_value = None
            value = {"type": "generic_alias", "origin": self.parse_value(), "args": self.parse_value()}
        elif tag == TAGS["union_type"]:
            self.last_value = None
            value = {"type": "union_type", "args": self.parse_value()}
        elif tag == TAGS["builtin_named"]:
            value = {"type": "builtin_named", "name": self.read_text_z()}
        elif tag == TAGS["builtin_exception"]:
            value = {"type": "builtin_exception", "name": self.read_text_z()}
        elif tag == TAGS["code_object"]:
            value = self.parse_code_object()
            self.code_objects.append(value)
        else:
            tag_name = TAG_NAMES.get(tag, "unknown")
            raise BlobParseError(
                f"section {self.section_name!r}: unknown tag 0x{tag:02x} ({tag_name}) "
                f"at offset {self.offset - 1}"
            )

        self.last_value = value
        return value

    def parse_sequence_items(self, count):
        self.last_value = None
        return [self.parse_value() for _ in range(count)]

    def parse_dict(self, count):
        self.last_value = None
        keys = [self.parse_value() for _ in range(count)]

        self.last_value = None
        values = [self.parse_value() for _ in range(count)]

        return {repr(key): value for key, value in zip(keys, values)}

    def parse_large_int(self, sign=None):
        if self.blob_format == "legacy":
            part_count = self.read_varint()
            value = 0
            for _ in range(part_count):
                value = (value << 31) + self.read_varint()
            return sign * value

        sign_byte = self.read_byte()
        part_count = self.read_count32()
        value = 0

        for _ in range(part_count):
            value = (value << 64) + self.read_u64()

        if sign_byte == ord("-"):
            return -value
        if sign_byte in (ord("+"), 0):
            return value

        raise BlobParseError(
            f"section {self.section_name!r}: unknown large int sign byte 0x{sign_byte:02x}"
        )

    def parse_special_float(self):
        value = self.read_byte()

        if value == 0:
            return 0.0
        if value == 1:
            return -0.0
        if value == 2:
            return math.nan
        if value == 3:
            return -math.nan
        if value == 4:
            return math.inf
        if value == 5:
            return -math.inf

        raise BlobParseError(f"unknown special float value {value}")

    def parse_bytes_value(self, size):
        if size is None:
            data = self.read_zbytes()
        else:
            data = self.read(size)

        value = BytesValue(data)
        self.bytes_values.append(value)
        return value

    def parse_code_object(self):
        flags = self.read_varint()
        name = self.parse_value()
        line = self.read_varint() + 1
        varnames = self.parse_value()
        arg_count = self.read_varint()

        result = {
            "type": "code_object",
            "name": name,
            "line": line,
            "flags": flags,
            "kind": code_kind(flags),
            "varnames": varnames,
            "arg_count": arg_count,
            "optimized": bool(flags & CODE_FLAG_OPTIMIZED),
            "newlocals": bool(flags & CODE_FLAG_NEWLOCALS),
            "varargs": bool(flags & CODE_FLAG_VARARGS),
            "varkeywords": bool(flags & CODE_FLAG_VARKEYWORDS),
        }

        if flags & CODE_FLAG_QUALNAME:
            result["qualname_owner"] = self.parse_value()

        if flags & CODE_FLAG_FREE_VARS:
            result["free_vars"] = self.parse_value()

        if flags & CODE_FLAG_KW_ONLY:
            result["kw_only_count"] = self.read_varint() + 1

        if flags & CODE_FLAG_POS_ONLY:
            result["pos_only_count"] = self.read_varint() + 1

        return result


def code_kind(flags):
    kind = flags & CODE_KIND_MASK

    if kind == CODE_KIND_GENERATOR:
        return "generator"
    if kind == CODE_KIND_COROUTINE:
        return "coroutine"
    if kind == CODE_KIND_ASYNCGEN:
        return "asyncgen"

    return "normal"


def bytes_preview(data, limit=80):
    text = data[:limit].decode("utf-8", "replace")
    if len(data) > limit:
        text += "..."
    return text


def safe_json(value):
    if isinstance(value, BlobDataValue):
        return value.as_summary()
    if isinstance(value, BytesValue):
        return value.as_summary()
    if isinstance(value, bytes):
        return {"type": "bytes", "size": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, complex):
        return {"type": "complex", "real": value.real, "imag": value.imag}
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value)

    return repr(value)


def try_marshal_code_summary(data):
    try:
        code = marshal.loads(data)
    except Exception:
        return None

    if not hasattr(code, "co_name"):
        return None

    return {
        "co_name": code.co_name,
        "co_filename": code.co_filename,
        "co_firstlineno": code.co_firstlineno,
        "co_argcount": code.co_argcount,
        "co_consts_count": len(code.co_consts),
        "co_names_count": len(code.co_names),
    }


def read_c_string(data, offset):
    end = data.find(b"\0", offset)
    if end < 0:
        raise BlobParseError(f"unterminated top-level blob name at offset {offset}")

    return data[offset:end], end + 1


def candidate_blob_offsets(data):
    offsets = [0]
    bytecode_offset = data.find(b".bytecode\0")
    if 0 < bytecode_offset < 64:
        offsets.append(bytecode_offset)
    if len(data) > 8:
        offsets.append(8)

    result = []
    for offset in offsets:
        if offset not in result:
            result.append(offset)
    return result


def split_top_level_blob_from(data, offset):
    sections = []

    while offset < len(data):
        name_bytes, offset = read_c_string(data, offset)

        if offset + 4 > len(data):
            raise BlobParseError(f"missing section size for {name_bytes!r}")

        size = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        if offset + size > len(data):
            raise BlobParseError(
                f"section {name_bytes!r} claims {size} bytes, only {len(data) - offset} remain"
            )

        section_data = data[offset : offset + size]
        offset += size
        name = name_bytes.decode("utf-8", "replace")
        sections.append((name, section_data))

    return sections


def split_top_level_blob(data):
    errors = []

    for offset in candidate_blob_offsets(data):
        try:
            return split_top_level_blob_from(data, offset)
        except BlobParseError as exc:
            errors.append(f"offset {offset}: {exc}")

    raise BlobParseError("; ".join(errors))


def parse_section(name, section_data, blob_format="fixed"):
    if len(section_data) < 2:
        raise BlobParseError(f"section {name!r} too small")

    expected_count = struct.unpack_from("<H", section_data, 0)[0]
    reader = Reader(section_data[2:], name, blob_format=blob_format)
    values = []

    for _ in range(expected_count):
        values.append(reader.parse_value())

    end_tag = reader.read_byte() if reader.remaining() else None
    if end_tag != TAGS["end"]:
        raise BlobParseError(
            f"section {name!r}: expected end tag 0x{TAGS['end']:02x}, got {end_tag!r}"
        )

    return {
        "name": name,
        "size": len(section_data),
        "format": blob_format,
        "count": expected_count,
        "trailing_bytes": reader.remaining(),
        "values": values,
        "strings": reader.strings,
        "bytes_values": reader.bytes_values,
        "blob_values": reader.blob_values,
        "code_objects": reader.code_objects,
    }


def parse_sections_with_format(sections, blob_format):
    parsed_sections = []
    parse_errors = []

    for section_index, (name, section_data) in enumerate(sections):
        try:
            section = parse_section(name, section_data, blob_format=blob_format)
        except BlobParseError as exc:
            parse_errors.append(
                {
                    "index": section_index,
                    "section": name,
                    "size": len(section_data),
                    "head_hex": section_data[:32].hex(),
                    "format": blob_format,
                    "error": str(exc),
                }
            )
        else:
            section["_top_level_index"] = section_index
            parsed_sections.append(section)

    return parsed_sections, parse_errors


def parse_sections(sections, blob_format="auto"):
    if blob_format != "auto":
        parsed_sections, parse_errors = parse_sections_with_format(sections, blob_format)
        return blob_format, parsed_sections, parse_errors

    candidates = []
    for candidate_format in ("fixed", "legacy"):
        parsed_sections, parse_errors = parse_sections_with_format(sections, candidate_format)
        candidates.append((len(parse_errors), -len(parsed_sections), candidate_format, parsed_sections, parse_errors))

    _error_count, _negative_parsed_count, chosen_format, parsed_sections, parse_errors = min(candidates)
    return chosen_format, parsed_sections, parse_errors


def dump_blob_values(parsed_sections, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []

    for section in parsed_sections:
        safe_section = section["name"] or "global"
        safe_section = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in safe_section)

        for index, blob_value in enumerate(section["blob_values"]):
            suffix = ".marshal" if blob_value.code_summary is not None else ".bin"
            filename = output_dir / f"{safe_section}_{index:04d}{suffix}"
            filename.write_bytes(blob_value.data)
            written.append(str(filename))

    return written


def main():
    parser = argparse.ArgumentParser(description="Inspect a dumped Nuitka constant blob ID 3 file.")
    parser.add_argument("blob", type=Path, help="constant_blob_id3.bin")
    parser.add_argument("--limit", type=int, default=8, help="number of decoded values to print per section")
    parser.add_argument("--strings", action="store_true", help="print decoded strings per section")
    parser.add_argument("--string-limit", type=int, default=40, help="number of strings to print per section")
    parser.add_argument("--json", type=Path, default=None, help="write parsed summary to JSON")
    parser.add_argument(
        "--blob-format",
        "--blob-version",
        choices=("auto", "fixed", "legacy"),
        default="auto",
        help="Nuitka constants stream format: auto, fixed/newer, or legacy/older.",
    )
    parser.add_argument("--dump-blobdata", type=Path, default=None, help="dump embedded BlobData entries to this directory")
    args = parser.parse_args()

    data = args.blob.read_bytes()
    sections = split_top_level_blob(data)
    chosen_format, parsed_sections, parse_errors = parse_sections(sections, args.blob_format)
    parsed_by_index = {section["_top_level_index"]: section for section in parsed_sections}
    errors_by_index = {item["index"]: item for item in parse_errors}

    print(f"Input   : {args.blob}")
    print(f"Size    : {len(data)} bytes")
    print(f"Sections: {len(sections)}")
    print(f"Format  : {chosen_format}")

    for section_index, (name, section_data) in enumerate(sections):
        section = parsed_by_index.get(section_index)
        if section is None:
            error = errors_by_index[section_index]["error"]
            print()
            print(f"[{name or '<global>'}] size={len(section_data)} parse_error={error}")
            continue

        print()
        print(f"[{name or '<global>'}] size={section['size']} constants={section['count']} trailing={section['trailing_bytes']}")
        print(
            "  decoded: "
            f"strings={len(section['strings'])} "
            f"bytes={len(section['bytes_values'])} "
            f"blob_data={len(section['blob_values'])} "
            f"code_objects={len(section['code_objects'])}"
        )

        for index, value in enumerate(section["values"][: args.limit]):
            print(f"  value[{index}] = {json.dumps(value, default=safe_json, ensure_ascii=False)}")

        if args.strings:
            unique_strings = []
            seen = set()
            for string in section["strings"]:
                if string not in seen:
                    seen.add(string)
                    unique_strings.append(string)

            for index, string in enumerate(unique_strings[: args.string_limit]):
                print(f"  string[{index}] = {string!r}")

    if args.dump_blobdata is not None:
        written = dump_blob_values(parsed_sections, args.dump_blobdata)
        print()
        print(f"Dumped BlobData entries: {len(written)}")
        print(f"BlobData output dir    : {args.dump_blobdata}")

    if args.json is not None:
        summary = {
            "input": str(args.blob),
            "size": len(data),
            "requested_blob_format": args.blob_format,
            "chosen_blob_format": chosen_format,
            "section_count": len(sections),
            "parsed_section_count": len(parsed_sections),
            "parse_error_count": len(parse_errors),
            "sections": [],
            "parse_errors": parse_errors,
        }

        for section_index, (name, section_data) in enumerate(sections):
            parsed = parsed_by_index.get(section_index)
            if parsed is None:
                summary["sections"].append(
                    {
                        "index": section_index,
                        "name": name,
                        "size": len(section_data),
                        "head_hex": section_data[:32].hex(),
                        "parse_error": errors_by_index.get(section_index, {}).get("error"),
                    }
                )
            else:
                summary["sections"].append(
                    {
                        "index": section_index,
                        "name": parsed["name"],
                        "size": parsed["size"],
                        "format": parsed["format"],
                        "count": parsed["count"],
                        "trailing_bytes": parsed["trailing_bytes"],
                        "strings": parsed["strings"],
                        "blob_data": [blob.as_summary() for blob in parsed["blob_values"]],
                        "code_objects": parsed["code_objects"],
                        "values_preview": parsed["values"][: args.limit],
                        "parse_error": None,
                    }
                )

        args.json.write_text(json.dumps(summary, default=safe_json, indent=2, ensure_ascii=False), encoding="utf-8")
        print()
        print(f"Wrote JSON summary: {args.json}")


if __name__ == "__main__":
    main()
