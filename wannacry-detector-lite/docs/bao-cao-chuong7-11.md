## CHƯƠNG 7: PHÂN TÍCH CẤU TRÚC PE (PE ANALYZER)

### 7.1 Lớp PEResult và các trường dữ liệu

`pe_analyzer.py` định nghĩa lớp `PEResult` chứa kết quả phân tích:

```python
class PEResult:
    is_pe: bool              # File có phải PE không?
    is_packed: bool          # Có bị pack không?
    packer_hint: str | None  # Tên packer nếu phát hiện được
    num_sections: int        # Số lượng sections
    section_names: list[str] # Danh sách tên section
    has_wannacry_section: bool      # Có .wnry hoặc .wncry không?
    has_suspicious_imports: bool    # Có import Crypto API không?
    suspicious_imports: list[str]   # Danh sách imports nghi ngờ
    suspicion_score: float   # Điểm nghi ngờ tổng hợp [0.0, 1.0]
```

### 7.2 Phát hiện Packer

Packer là công cụ nén/mã hóa file PE để che giấu code thực. WannaCry có thể được đóng gói bằng các packer như UPX. Hàm `_detect_packer()` kiểm tra:

**Bước 1:** So khớp tên section với danh sách packer đã biết:
```python
PACKER_SIGNS = {"UPX", "ASPack", "MPRESS", "PECompact",
                "Themida", "VMProtect", "Enigma"}
```

**Bước 2:** Phát hiện section bất thường (tên dài > 8 ký tự, không nằm trong `NORMAL_SECTIONS`):
```python
NORMAL_SECTIONS = {".text", ".data", ".rdata", ".rsrc",
                   ".reloc", ".bss", ".idata", ".edata"}
odd_sections = section_names - NORMAL_SECTIONS
if odd_sections and any(len(s) > 8 for s in odd_sections):
    return True, None
```

**Bước 3:** Heuristic: file PE chỉ có ≤ 2 sections thường là đã bị pack.

### 7.3 Phát hiện WannaCry Section

```python
WANNACRY_SECTIONS = {".wnry", ".wncry"}
for section in pe.sections:
    name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
    if name in WANNACRY_SECTIONS:
        result.has_wannacry_section = True
```

Section `.wnry` trong file WannaCry chứa module `wcry.exe` nhúng bên trong — đây là IOC mạnh và hiếm gặp ở file lành tính.

### 7.4 Công thức tính suspicion_score

Điểm nghi ngờ được tính theo hệ thống cộng điểm có trọng số:

$$\text{score} = 0.4 \cdot \mathbf{1}[\text{has\_wnry\_section}] + \min(|\text{susp\_imports}| \times 0.1, 0.3) + 0.2 \cdot \mathbf{1}[\text{is\_packed}] + 0.1 \cdot \mathbf{1}[\text{num\_sections} < 3]$$

$$\text{suspicion\_score} = \min(\text{score}, 1.0)$$

Ví dụ: file có section `.wnry` (0.4) + 3 suspicious imports (0.3) + bị pack (0.2) = **0.9** — rất nghi ngờ.

---

## CHƯƠNG 8: ENGINE YARA RULES

### 8.1 Tổng quan lớp YaraEngine

`yara_engine.py` bọc thư viện `yara-python` với interface thuần Python:

```python
@dataclass
class YaraMatch:
    rule_name: str
    tags: list[str]
    meta: dict[str, str]
    strings_matched: list[str]

class YaraEngine:
    def __init__(self, rules_path: Path, compile_on_load: bool = True):
        self._rules: yara.Rules | None = None
        if compile_on_load:
            self.compile()  # Compile ngay khi khởi động
```

Compile rules một lần khi khởi động và tái sử dụng cho mọi lần scan — đây là tối ưu quan trọng vì compile YARA rules tốn thời gian.

### 8.2 Bộ 7 YARA Rules — wannacry.yar

Tất cả 7 rules đều có điều kiện chung là `uint16(0) == 0x5A4D` — kiểm tra magic bytes PE, đảm bảo chỉ match với file PE thật sự.

#### Rule 1: WannaCry_Strings
Phát hiện các chuỗi định danh cứng trong binary:
```yara
strings:
    $s1 = "WANACRY!" ascii wide nocase
    $s2 = "Wanna Decryptor" ascii wide nocase
    $s3 = ".wncry" ascii wide
    $s4 = "@WanaDecryptor@" ascii wide
    $s5 = "tasksche.exe" ascii wide nocase
    $s6 = "TaskStart" ascii wide
    $s7 = "wcry@123" ascii wide
    $s8 = "WanaCrypt0r" ascii wide nocase
condition:
    uint16(0) == 0x5A4D and any of them
```
Chuỗi `wcry@123` là hardcoded password dùng để mở file zip nhúng trong WannaCry — IOC đặc biệt đáng tin cậy.

#### Rule 2: WannaCry_Killswitch (severity: critical)
```yara
$domain1 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide
```
Sự xuất hiện của killswitch domain trong binary là bằng chứng chắc chắn về WannaCry — không có phần mềm lành tính nào chứa domain này.

#### Rule 3: WannaCry_Mutex
```yara
$mutex1 = "MsWinZonesCacheCounterMutexA" ascii wide
$mutex2 = "MsWinZonesCacheCounterMutex0" ascii wide
$mutex3 = "Global\\MsWinZonesCacheCounterMutexA" ascii wide
```
Mutex được WannaCry dùng để kiểm tra xem đã có instance nào đang chạy chưa, tránh lây nhiễm hai lần trên cùng một máy.

#### Rule 4: WannaCry_Crypto_Imports (yêu cầu kết hợp)
```yara
condition:
    uint16(0) == 0x5A4D and
    (4 of ($import*)) and        // Ít nhất 4 Crypto API
    (any of ($section, $ext))    // VÀ có section .wnry hoặc .wncry
```
Rule này yêu cầu corroboration: phải có cả Crypto API **và** WannaCry section — giảm false positive so với chỉ check imports.

#### Rule 5: WannaCry_Ransom_Note
Match các tên file ransom note đặc trưng: `@Please_Read_Me@.txt`, `@WanaDecryptor@.exe`, `!Please Read Me!.hta`.

#### Rule 6: WannaCry_File_Extension
Yêu cầu ít nhất 2 trong 4 phần mở rộng: `.WNCRY`, `.wcry`, `.WNCRYT`, `.WNCYRT`.

#### Rule 7: WannaCry_SMB_Exploit (severity: critical)
```yara
$smb1 = "EternalBlue" wide ascii nocase
$smb2 = "DoublePulsar" wide ascii nocase
```
Sự xuất hiện của tên exploit NSA trong binary là IOC mạnh liên quan đến WannaCry hoặc các mã độc dùng EternalBlue.

### 8.3 Tích hợp vào Pipeline

```python
# Trong _analyze_file() của scanner.py:
matches = self.yara_engine.scan_file(file_path)
yara_matches = [m.rule_name for m in matches]

# Trong _combine_verdict():
if yara_matches:
    return "wannacry"  # YARA match = verdict tức thì
```

Ưu tiên tuyệt đối của YARA đảm bảo: nếu file chứa IOC WannaCry đã biết, không cần đợi ML hay PE để kết luận.

---

## CHƯƠNG 9: CƠ CHẾ KẾT HỢP PHÁN QUYẾT VÀ GIẢM THIỂU FALSE POSITIVE

### 9.1 Hàm _combine_verdict()

Đây là "não" của hệ thống, kết hợp tín hiệu từ 3 lớp thành phán quyết cuối:

```python
def _combine_verdict(ml_label, ml_score, ml_threshold, pe_score, yara_matches):
    # Ưu tiên 1: YARA match bất kỳ → wannacry
    if yara_matches:
        return "wannacry"

    # Ưu tiên 2: ML mạnh + PE hỗ trợ → wannacry
    if ml_label == "wannacry" and ml_score >= ml_threshold:
        if pe_score >= 0.3:
            return "wannacry"
        return "suspicious"  # ML mạnh nhưng PE không đồng ý

    # Ưu tiên 3: PE đủ mạnh độc lập
    if pe_score >= 0.6:
        return "suspicious"

    # Ưu tiên 4: ML borderline
    if ml_score >= ml_threshold * 0.8:  # 80% × 0.7 = 0.56
        return "suspicious"

    return "benign"
```

Thiết kế này thể hiện nguyên tắc **corroboration** (cần xác nhận từ nhiều nguồn): ML cần PE hỗ trợ để đạt verdict `wannacry` — giảm đáng kể false positive so với chỉ dùng một lớp.

### 9.2 Bảng phán quyết đầy đủ

| YARA | ML score | PE score | Verdict |
|------|----------|----------|---------|
| Có match | bất kỳ | bất kỳ | **wannacry** |
| Không | ≥ 0.7 | ≥ 0.3 | **wannacry** |
| Không | ≥ 0.7 | < 0.3 | **suspicious** |
| Không | bất kỳ | ≥ 0.6 | **suspicious** |
| Không | ≥ 0.56 | bất kỳ | **suspicious** |
| Không | < 0.56 | < 0.6 | **benign** |

### 9.3 Cơ chế Whitelist (FPReducer)

`fp_reducer.py` cung cấp hai phương thức whitelist để loại bỏ false positive:

**Whitelist theo hash SHA-256:**
```python
def is_whitelisted_hash(self, file_path: Path) -> bool:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest().lower() in self.whitelist_hashes
```

**Whitelist theo path prefix:**
```python
def is_whitelisted_path(self, file_path: Path) -> bool:
    resolved = file_path.resolve()
    for prefix in self.whitelist_paths:
        if str(resolved).startswith(str(Path(prefix).resolve())):
            return True
    return False
```

File được whitelist **trước khi** đi vào pipeline scan — tiết kiệm tài nguyên và ngăn cảnh báo sai cho file hệ thống đã xác minh (ví dụ: `C:\Windows\System32\`).

### 9.4 Pipeline quét song song

`ThreadPoolExecutor` với `max_workers=4` (mặc định) cho phép quét đồng thời nhiều file:

```python
with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
    future_map = {executor.submit(self._analyze_file, fp): fp for fp in files}
    for future in as_completed(future_map):
        results.append(future.result())
```

Trên CPU i7-12700H (12 cores), `max_workers` có thể tăng lên 8–12 để tận dụng tối đa phần cứng.

---

## CHƯƠNG 10: GIAO DIỆN NGƯỜI DÙNG

### 10.1 Giao diện dòng lệnh CLI

`main.py` hỗ trợ các tham số CLI:

```bash
# Quét thư mục với verbose output
python main.py --scan /path/to/target --verbose

# Quét và xuất báo cáo CSV + JSON
python main.py --scan /path/to/target --report-format json,csv

# Dùng file config tùy chỉnh
python main.py --scan /path/to/target --config custom_config.json

# Mở GUI
python main.py --gui
```

Kết quả CLI hiển thị màu phân biệt: `wannacry` màu đỏ, `suspicious` màu vàng, `benign` màu xanh.

### 10.2 Giao diện đồ họa GUI (CustomTkinter)

GUI được xây dựng bằng `customtkinter` — thư viện mở rộng tkinter với giao diện hiện đại hỗ trợ dark mode. Ba tab chức năng:

**Tab Dashboard:**
- Hiển thị trạng thái 3 engine: ML (model loaded/not), YARA (rules compiled/not), PE (always ready).
- Tóm tắt lần quét gần nhất: tổng files, số wannacry, suspicious, benign.

**Tab Scan:**
- Nút "Browse" chọn thư mục hoặc file.
- Progress bar real-time trong quá trình quét.
- Bảng kết quả với màu sắc phân biệt verdict.
- Nút export báo cáo CSV/JSON/PDF.

**Tab Training:**
- Tạo dataset tổng hợp (gọi `scripts/build_wannacry_dataset.py`).
- Huấn luyện model (gọi `train_model.py`).
- Hiển thị log training real-time.

### 10.3 Quản lý cấu hình (config_manager.py)

Cấu hình mặc định được merge với config từ file JSON người dùng cung cấp:

```json
{
  "scanner": {
    "max_workers": 4,
    "recursive": true,
    "scan_extensions": [".exe", ".dll", ".sys", ".bin"],
    "max_file_size_mb": 100,
    "whitelist_hashes": [],
    "whitelist_paths": []
  },
  "ml_engine": {
    "model_path": "models/wannacry_rf.pkl",
    "threshold": 0.7
  },
  "yara_engine": {
    "rules_path": "rules/wannacry.yar",
    "compile_on_load": true
  },
  "report": {
    "output_dir": "reports",
    "formats": ["csv", "json"]
  }
}
```

`validate_config()` kiểm tra kiểu dữ liệu và ràng buộc: `max_workers >= 1`, `0 < threshold <= 1`, `max_file_size_mb > 0`.

---

## CHƯƠNG 11: HỆ THỐNG BÁO CÁO

### 11.1 Dataclass ScanResult

Mỗi file được scan tạo ra một `ScanResult`:

```python
@dataclass
class ScanResult:
    file_path: str           # Đường dẫn tuyệt đối
    verdict: str             # "wannacry" / "suspicious" / "benign" / "error"
    ml_score: float = 0.0   # Xác suất WannaCry từ ML (0.0–1.0)
    pe_suspicion_score: float = 0.0  # Điểm nghi ngờ PE (0.0–1.0)
    yara_matches: list[str] = field(default_factory=list)  # Rule names
    file_size: int = 0       # Bytes
    sha256: str = ""         # Hash SHA-256
    scan_time: str = ""      # ISO 8601 timestamp UTC
```

### 11.2 Báo cáo CSV

```python
fieldnames = ["file_path", "verdict", "ml_score", "pe_suspicion_score",
              "yara_matches", "file_size", "sha256", "scan_time"]
```

File CSV có tên dạng `wannacry_scan_20260502_001234.csv` — timestamp UTC giúp phân biệt các lần scan. `yara_matches` được join bằng dấu phẩy thành một chuỗi.

### 11.3 Báo cáo JSON

```json
{
  "scan_time": "2026-05-02T00:12:34+00:00",
  "total_files": 150,
  "verdicts": {
    "wannacry": 3,
    "suspicious": 7,
    "benign": 140
  },
  "results": [...]
}
```

JSON report kèm summary statistics ở level cao — thuận tiện cho tích hợp với SIEM hoặc dashboard.

### 11.4 Summary Statistics

```python
def generate_summary(self, results: list[ScanResult]) -> dict:
    return {
        "total": len(results),
        "wannacry": sum(1 for r in results if r.verdict == "wannacry"),
        "suspicious": sum(1 for r in results if r.verdict == "suspicious"),
        "benign": sum(1 for r in results if r.verdict == "benign"),
        "yara_hits": sum(1 for r in results if r.yara_matches),
        "ml_positives": sum(1 for r in results if r.ml_score >= 0.7),
    }
```

`yara_hits` và `ml_positives` là hai chỉ số riêng biệt — giúp phân tích tại sao một file được đánh dấu (YARA hits thì chắc chắn hơn ML alone).
