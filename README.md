# nuitka_tools_clean

Bộ công cụ hỗ trợ trích xuất artifact phục vụ static analysis từ file PE được build bằng Nuitka.

Repository này hiện có 2 script chính:

- `nuitka_auto_export.py`: tự động nhận diện backend PE hoặc onefile wrapper, trích xuất payload và constant blob, rồi xuất ra các artifact để phân tích.
- `read_constant_blob.py`: đọc và parse trực tiếp file `constant_blob_id3.bin` của Nuitka.

## Chức năng chính

### `nuitka_auto_export.py`

Script này tự động hóa các bước cơ bản khi phân tích file Nuitka trên Windows:

- phát hiện backend PE hoặc onefile wrapper
- trích xuất `RT_RCDATA` ID `27` khi là onefile
- tách payload onefile
- tìm backend PE chứa `RT_RCDATA` ID `3`
- dump và parse constant blob của Nuitka
- xuất constants theo từng module/section
- dump `BlobData`, bytes constants, marshal candidates, `.pyc` candidates
- tạo helper script cho IDA để dò string xrefs
- tạo file context để hỗ trợ AI-assisted reversing

### `read_constant_blob.py`

Script này đọc trực tiếp file `constant_blob_id3.bin` và:

- chia top-level blob thành các section
- parse constants theo format `auto`, `fixed`, hoặc `legacy`
- hiển thị strings/code objects/blob data
- có thể dump `BlobData` ra file riêng
- có thể ghi summary ra JSON

## Yêu cầu

Cài dependency Python:

```bash
pip install -r requirements.txt
```

`requirements.txt` hiện dùng:

- `pefile`
- `zstandard`

Ngoài ra, `nuitka_auto_export.py` yêu cầu các file sau nằm cùng thư mục:

- `dump.py`
- `read_constant_blob.py`

## Cài skill cho Claude Code

Repo kèm sẵn skill `nuitka-dump/` (chứa `SKILL.md`) — quy trình dump + static reversing Nuitka để Claude Code tự làm theo (one-click dump, đọc output, và kỹ thuật `mod_consts[]` để map constant string về hàm C trong IDA).

Cài global (dùng cho mọi project trên máy):

```bash
# macOS / Linux
mkdir -p ~/.claude/skills
cp -r nuitka-dump ~/.claude/skills/
```

```powershell
# Windows PowerShell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills" | Out-Null
Copy-Item -Recurse -Force nuitka-dump "$env:USERPROFILE\.claude\skills\"
```

Mở session Claude Code mới rồi gõ `/nuitka-dump`, hoặc cứ nhắc tới việc dump/reverse Nuitka là skill tự kích hoạt. Skill chỉ là text hướng dẫn — để bước dump chạy thật vẫn cần clone repo này + `pip install -r requirements.txt` + Python ≥ 3.10.

## Cách dùng

### 1. Tự động export từ file Nuitka

```bash
python nuitka_auto_export.py target.exe -o target_export
```

Ép đi theo luồng onefile:

```bash
python nuitka_auto_export.py target.exe -o target_export --onefile-only
```

Chỉ định format constant blob:

```bash
python nuitka_auto_export.py target.exe -o target_export --blob-format auto
python nuitka_auto_export.py target.exe -o target_export --blob-format fixed
python nuitka_auto_export.py target.exe -o target_export --blob-format legacy
```

Tắt redact chuỗi có dạng Token/Bearer trong output:

```bash
python nuitka_auto_export.py target.exe -o target_export --no-redact
```

### 2. Đọc trực tiếp constant blob

```bash
python read_constant_blob.py constant_blob_id3.bin
```

Ghi summary ra JSON:

```bash
python read_constant_blob.py constant_blob_id3.bin --json blob_summary.json
```

In strings:

```bash
python read_constant_blob.py constant_blob_id3.bin --strings --string-limit 100
```

Dump `BlobData` ra thư mục riêng:

```bash
python read_constant_blob.py constant_blob_id3.bin --dump-blobdata dumped_blobdata
```

## Output của `nuitka_auto_export.py`

Thư mục output thường chứa các artifact sau:

- `blob_summary.json`: tổng quan constant blob
- `constants_full.json`: toàn bộ constants đã parse
- `constants_preview.json`: bản preview rút gọn
- `code_objects.json`: danh sách code object
- `strings_by_section.json`: strings theo section
- `blobdata_manifest.json`: manifest cho BlobData
- `bytes_constants_manifest.json`: manifest cho bytes constants
- `export_manifest.json`: manifest tổng
- `ai_context.md`: context ngắn gọn để dùng với AI/reversing workflow
- `modules/`: constants theo từng module/section
- `blobdata/`: BlobData đã dump
- `bytecode/`: marshal hoặc `.pyc` candidates
- `ida/ida_nuitka_helper.py`: helper script cho IDA

## Gợi ý workflow

1. Chạy `nuitka_auto_export.py` trên file `.exe` hoặc `.dll` cần phân tích.
2. Mở backend PE được trích xuất trong IDA.
3. Chạy `ida/ida_nuitka_helper.py` trong IDA.
4. Đối chiếu `constants_full.json`, `strings_by_section.json`, `code_objects.json` và các file trong `modules/` để map native code với constant data của Nuitka.

## Ghi chú

- `--blob-format auto` là lựa chọn mặc định và nên dùng trước.
- Một số mẫu Nuitka cũ dùng `legacy` blob format.
- Output text/JSON hiện đã được ghi theo cách an toàn với dữ liệu Unicode đặc biệt của Nuitka, kể cả trường hợp có lone surrogate trong constant strings.
- Tool này hướng tới static reversing và phân tích artifact, không nhằm unpack hoàn chỉnh hay phục hồi đầy đủ source code gốc.
