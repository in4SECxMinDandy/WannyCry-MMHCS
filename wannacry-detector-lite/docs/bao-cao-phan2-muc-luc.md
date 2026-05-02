# MỤC LỤC — BÁO CÁO BÀI TẬP LỚN

**Đề tài:** Nghiên cứu và Xây dựng Công cụ Phát hiện Mã độc WannaCry
dựa trên Học máy, Phân tích PE và YARA Rules
**Sinh viên:** Trần Huy Hoàng — B23DCAT190 — An toàn thông tin — PTIT

> **Ghi chú:** Mục lục được xây dựng bám sát code nguồn thực tế của dự án
> `wannacry-detector-lite`. Chỉ trình bày các tính năng đã được triển khai.

---

## CHƯƠNG 1: TỔNG QUAN VỀ RANSOMWARE VÀ WANNACRY

### 1.1 Khái niệm Ransomware
#### 1.1.1 Định nghĩa và phân loại
#### 1.1.2 Vòng đời tấn công điển hình

### 1.2 Ransomware WannaCry
#### 1.2.1 Bối cảnh xuất hiện (tháng 5/2017)
#### 1.2.2 Cơ chế hoạt động kỹ thuật
#### 1.2.3 Các IOC đặc trưng: mutex, killswitch domain, phần mở rộng `.wncry`
#### 1.2.4 Vector lây lan qua lỗ hổng SMB — EternalBlue (CVE-2017-0144)

### 1.3 Lý do chọn đề tài và tính cấp thiết

---

## CHƯƠNG 2: MỤC TIÊU VÀ PHẠM VI NGHIÊN CỨU

### 2.1 Mục tiêu nghiên cứu
#### 2.1.1 Mục tiêu tổng quát
#### 2.1.2 Mục tiêu cụ thể và các chỉ số đo lường (Precision, Recall, F1)

### 2.2 Phạm vi nghiên cứu
#### 2.2.1 Đối tượng phân tích: file PE (EXE, DLL, SYS, BIN) trên Windows
#### 2.2.2 Giới hạn: phân tích tĩnh, không sandbox động

### 2.3 Phương pháp nghiên cứu tổng quan

---

## CHƯƠNG 3: CƠ SỞ LÝ THUYẾT

### 3.1 Lý thuyết Entropy Shannon
#### 3.1.1 Công thức $H(X) = -\sum_{i} p_i \log_2 p_i$ và ý nghĩa
#### 3.1.2 Phân biệt entropy file bình thường vs. file mã hóa/nén
#### 3.1.3 Entropy theo từng section PE (`.text`, `.data`)

### 3.2 Kiểm định Chi-Square phân phối byte
#### 3.2.1 Công thức $\chi^2 = \sum_{i=0}^{255} \frac{(O_i - E_i)^2}{E_i}$
#### 3.2.2 Ứng dụng phát hiện dữ liệu ngẫu nhiên (dấu hiệu mã hóa)

### 3.3 Histogram byte 8 nhóm
#### 3.3.1 Phân vùng [0–255] thành 8 bin (mỗi bin 32 giá trị)
#### 3.3.2 Đặc trưng phân phối của file WannaCry vs. file lành tính

### 3.4 Định dạng Portable Executable (PE)
#### 3.4.1 Cấu trúc DOS Header, NT Header, Section Table
#### 3.4.2 Import Address Table (IAT) và Crypto API
#### 3.4.3 Magic bytes MZ (`0x5A4D`) và điều kiện YARA `uint16(0) == 0x5A4D`

### 3.5 Thuật toán Random Forest
#### 3.5.1 Bagging và Decision Tree
#### 3.5.2 Gini Impurity và Feature Importance
#### 3.5.3 SMOTE: cân bằng dữ liệu cho bài toán phát hiện mã độc

---

## CHƯƠNG 4: KIẾN TRÚC HỆ THỐNG TỔNG THỂ

### 4.1 Triết lý thiết kế đa lớp (Defense-in-Depth)
#### 4.1.1 Ưu điểm kết hợp ML + PE + YARA so với từng phương pháp đơn lẻ
#### 4.1.2 Cơ chế dự phòng: nếu một lớp thất bại, hai lớp còn lại vẫn hoạt động

### 4.2 Sơ đồ kiến trúc 3 lớp
#### 4.2.1 Lớp 1 — ML Engine: Random Forest 16 đặc trưng
#### 4.2.2 Lớp 2 — PE Analyzer: phân tích cấu trúc và packer
#### 4.2.3 Lớp 3 — YARA Engine: pattern matching theo rule

### 4.3 Luồng dữ liệu tổng thể
#### 4.3.1 Input: Path → Walker → Whitelist → 3 Engine song song
#### 4.3.2 Output: ScanResult → Verdict Combiner → Report

### 4.4 Cấu trúc module dự án
#### 4.4.1 `core/`: các engine phát hiện cốt lõi
#### 4.4.2 `rules/`: YARA rules tĩnh
#### 4.4.3 `gui/`, `scripts/`, `tests/`, `reports/`

---

## CHƯƠNG 5: MODULE TRÍCH XUẤT ĐẶC TRƯNG

### 5.1 Tổng quan 16 đặc trưng (`feature_extractor.py`)
#### 5.1.1 Bảng ánh xạ feature_1 → feature_16 và tên ngữ nghĩa
#### 5.1.2 Lý do lựa chọn tập đặc trưng này

### 5.2 Nhóm đặc trưng Entropy (feature_1–3)
#### 5.2.1 `feature_1 = entropy_full`: Entropy toàn bộ file
#### 5.2.2 `feature_2 = entropy_text`: Entropy section `.text`
#### 5.2.3 `feature_3 = entropy_data`: Entropy section `.data`
#### 5.2.4 Cài đặt hàm `_shannon_entropy(data: bytes) -> float`

### 5.3 Nhóm đặc trưng phân phối byte (feature_4–12)
#### 5.3.1 `feature_4 = chi_square`: thống kê $\chi^2$
#### 5.3.2 `feature_5` → `feature_12`: 8-bin histogram chuẩn hóa
#### 5.3.3 Cài đặt `_chi_square()` và `_byte_histogram_bins()`

### 5.4 Nhóm đặc trưng cấu trúc PE (feature_13–16)
#### 5.4.1 `feature_13 = file_size_log`: $\log_2(\text{file\_size})$
#### 5.4.2 `feature_14 = num_sections`: số PE sections
#### 5.4.3 `feature_15 = exec_ratio`: tỷ lệ section thực thi
#### 5.4.4 `feature_16 = suspicious_imports`: số import API nghi ngờ (14 API)

### 5.5 Danh sách `SUSPICIOUS_IMPORTS` và lý do chọn lọc
#### 5.5.1 Crypto API: `CryptEncrypt`, `CryptDecrypt`, `CryptGenRandom`
#### 5.5.2 File traversal: `FindFirstFileW`, `FindNextFileW`, `MoveFileExW`
#### 5.5.3 Network/Exec: `InternetOpenA`, `WinExec`, `CreateRemoteThread`

### 5.6 Xử lý ngoại lệ và file không hợp lệ
#### 5.6.1 File < 64 bytes → trả về `None`
#### 5.6.2 `pefile.PEFormatError` → bỏ qua file không phải PE

---

## CHƯƠNG 6: ENGINE HỌC MÁY — RANDOM FOREST

### 6.1 Kiến trúc lớp `MLEngine` (`ml_engine.py`)
#### 6.1.1 Khởi tạo: `model_path`, `threshold = 0.7`
#### 6.1.2 Load model từ file `.pkl` bằng `joblib`

### 6.2 Quy trình dự đoán
#### 6.2.1 `features_to_array()`: dict → numpy array shape `(1, 16)`
#### 6.2.2 `predict_proba()`: lấy xác suất class `wannacry`
#### 6.2.3 Ngưỡng phân loại: `score >= threshold` → label `wannacry`

### 6.3 Quy trình huấn luyện (`train_model.py`)
#### 6.3.1 Load CSV: các cột `feature_1..feature_16` + `label`
#### 6.3.2 SMOTE: kích hoạt khi `imbalance_ratio > 0.2`
#### 6.3.3 `train_test_split()` với `stratify=y`, `test_size=0.2`
#### 6.3.4 `RandomForestClassifier(n_estimators=200, max_depth=20, class_weight="balanced")`
#### 6.3.5 Cross-validation 5-fold và xuất top 5 Feature Importance

### 6.4 Siêu tham số và cấu hình
#### 6.4.1 Ảnh hưởng của `n_estimators` lên hiệu năng và thời gian
#### 6.4.2 `n_jobs=-1`: song song hóa trên toàn bộ CPU cores

---

## CHƯƠNG 7: PHÂN TÍCH CẤU TRÚC PE (PE ANALYZER)

### 7.1 Lớp `PEResult` và các trường dữ liệu (`pe_analyzer.py`)
#### 7.1.1 `is_pe`, `is_packed`, `packer_hint`, `num_sections`
#### 7.1.2 `has_wannacry_section`, `suspicious_imports`, `suspicion_score`

### 7.2 Phát hiện Packer (`_detect_packer()`)
#### 7.2.1 Danh sách `PACKER_SIGNS`: UPX, ASPack, Themida, VMProtect...
#### 7.2.2 Phát hiện section tên bất thường (> 8 ký tự hoặc không nằm trong `NORMAL_SECTIONS`)
#### 7.2.3 Heuristic: PE chỉ có ≤ 2 sections → nghi ngờ pack

### 7.3 Phát hiện IOC section WannaCry
#### 7.3.1 `WANNACRY_SECTIONS = {".wnry", ".wncry"}` → cộng +0.4 điểm
#### 7.3.2 Suspicious imports → cộng `min(count × 0.1, 0.3)` điểm
#### 7.3.3 Packer → +0.2; ít sections → +0.1

### 7.4 Công thức tính `suspicion_score ∈ [0.0, 1.0]`

---

## CHƯƠNG 8: ENGINE YARA RULES

### 8.1 Tổng quan YARA và lớp `YaraEngine` (`yara_engine.py`)
#### 8.1.1 Dataclass `YaraMatch`: `rule_name`, `tags`, `meta`, `strings_matched`
#### 8.1.2 Compile rules tại khởi động (`compile_on_load=True`)

### 8.2 Bộ 7 YARA Rules cho WannaCry (`wannacry.yar`)
#### 8.2.1 `WannaCry_Strings`: chuỗi `WANACRY!`, `WanaCrypt0r`, `.wncry`, `wcry@123`
#### 8.2.2 `WannaCry_Killswitch`: domain `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`
#### 8.2.3 `WannaCry_Mutex`: `MsWinZonesCacheCounterMutexA`
#### 8.2.4 `WannaCry_Crypto_Imports`: ≥ 4 Crypto API + section `.wnry`/`.wncry`
#### 8.2.5 `WannaCry_Ransom_Note`: `@Please_Read_Me@.txt`, `@WanaDecryptor@.exe`
#### 8.2.6 `WannaCry_File_Extension`: ≥ 2 trong `.WNCRY`, `.wcry`, `.WNCRYT`
#### 8.2.7 `WannaCry_SMB_Exploit`: `EternalBlue`, `DoublePulsar`

### 8.3 Điều kiện chung: `uint16(0) == 0x5A4D` (magic bytes PE)

### 8.4 Tích hợp vào pipeline
#### 8.4.1 `scan_file()`: match theo file path, timeout 60s
#### 8.4.2 `scan_bytes()`: match theo raw bytes (dùng trong tests)
#### 8.4.3 Bất kỳ rule khớp → Verdict Combiner trả về `wannacry` ngay lập tức

---

## CHƯƠNG 9: CƠ CHẾ KẾT HỢP PHÁN QUYẾT VÀ GIẢM THIỂU FALSE POSITIVE

### 9.1 Hàm `_combine_verdict()` trong `scanner.py`
#### 9.1.1 Bảng quy tắc ưu tiên (priority order)

| Điều kiện | Kết quả |
|---|---|
| `yara_matches` không rỗng | `wannacry` |
| `ml_label == "wannacry"` AND `pe_score >= 0.3` | `wannacry` |
| `ml_label == "wannacry"` AND `pe_score < 0.3` | `suspicious` |
| `pe_score >= 0.6` | `suspicious` |
| `ml_score >= threshold × 0.8` | `suspicious` |
| Còn lại | `benign` |

#### 9.1.2 Lý do YARA có độ ưu tiên cao nhất (zero false negative với IOC cụ thể)
#### 9.1.3 Yêu cầu corroboration: ML phải kết hợp PE để đạt verdict `wannacry`

### 9.2 Cơ chế Whitelist (`fp_reducer.py`)
#### 9.2.1 Whitelist theo SHA-256 hash: `is_whitelisted_hash()`
#### 9.2.2 Whitelist theo path prefix: `is_whitelisted_path()`
#### 9.2.3 Cấu hình qua `config.json`: `whitelist_hashes`, `whitelist_paths`

### 9.3 Pipeline quét song song (`scanner.py`)
#### 9.3.1 `ThreadPoolExecutor(max_workers=4)`: quét đồng thời nhiều file
#### 9.3.2 Bộ lọc trước khi quét: extension, kích thước tối đa (100 MB), whitelist

---

## CHƯƠNG 10: GIAO DIỆN NGƯỜI DÙNG

### 10.1 Giao diện dòng lệnh CLI (`main.py`)
#### 10.1.1 Tham số: `--scan PATH`, `--report-format json,csv`, `--config FILE`, `--verbose`
#### 10.1.2 Output terminal màu sắc phân biệt verdict

### 10.2 Giao diện đồ họa GUI (`gui/`, CustomTkinter)
#### 10.2.1 Tab Dashboard: trạng thái 3 engine + tóm tắt lần quét gần nhất
#### 10.2.2 Tab Scan: chọn thư mục, chạy quét, hiển thị kết quả từng file
#### 10.2.3 Tab Training: tạo dataset tổng hợp + huấn luyện mô hình

### 10.3 Quản lý cấu hình (`config_manager.py`)
#### 10.3.1 `DEFAULT_CONFIG`: 5 section (scanner, ml_engine, pe_analyzer, yara_engine, report)
#### 10.3.2 Merge config người dùng với default, validate kiểu dữ liệu

---

## CHƯƠNG 11: HỆ THỐNG BÁO CÁO

### 11.1 Dataclass `ScanResult` (`report_generator.py`)
#### 11.1.1 Các trường: `file_path`, `verdict`, `ml_score`, `pe_suspicion_score`, `yara_matches`, `sha256`

### 11.2 Định dạng xuất hỗ trợ
#### 11.2.1 CSV: `generate_csv()` — tên file có timestamp
#### 11.2.2 JSON: `generate_json()` — kèm summary statistics (tổng, wannacry, suspicious, benign)
#### 11.2.3 PDF: `pdf_reporter.py` — báo cáo trình bày chuyên nghiệp (tuỳ chọn)

### 11.3 Summary statistics
#### 11.3.1 `generate_summary()`: tổng file, yara_hits, ml_positives

---

## CHƯƠNG 12: XÂY DỰNG BỘ DỮ LIỆU THỰC NGHIỆM

### 12.1 Chiến lược xây dựng dataset tổng hợp
#### 12.1.1 Script `scripts/build_wannacry_dataset.py`
#### 12.1.2 Tham số: `--wannacry-count 500`, `--benign-count 2000`
#### 12.1.3 Giá trị đặc trưng được simulate dựa trên phân phối thực tế của WannaCry

### 12.2 Cấu trúc file CSV dataset
#### 12.2.1 Các cột: `feature_1..feature_16`, `label` (`wannacry`/`benign`)
#### 12.2.2 Xử lý giá trị missing: `fillna(0)`

### 12.3 Phân tích thống kê bộ dữ liệu
#### 12.3.1 Phân phối nhãn trước và sau SMOTE
#### 12.3.2 Thống kê mô tả các đặc trưng quan trọng nhất

---

## CHƯƠNG 13: KẾT QUẢ THỰC NGHIỆM VÀ ĐÁNH GIÁ

### 13.1 Môi trường thực nghiệm
#### 13.1.1 Phần cứng: Lenovo Legion 5 Pro 2022 (i7-12700H, 32GB DDR5, RTX 3050Ti)
#### 13.1.2 Phần mềm: Python 3.11, scikit-learn, yara-python, pefile, imbalanced-learn

### 13.2 Chỉ số đánh giá
#### 13.2.1 Precision: $P = \frac{TP}{TP + FP}$
#### 13.2.2 Recall: $R = \frac{TP}{TP + FN}$
#### 13.2.3 F1-Score: $F_1 = 2 \cdot \frac{P \cdot R}{P + R}$
#### 13.2.4 Confusion Matrix và AUC-ROC

### 13.3 Kết quả từng lớp phát hiện
#### 13.3.1 ML Engine: Precision/Recall/F1, top 5 Feature Importance
#### 13.3.2 PE Analyzer: phân phối `suspicion_score`, tỷ lệ phát hiện packer
#### 13.3.3 YARA Engine: tỷ lệ match theo từng rule trong 7 rules

### 13.4 Kết quả hệ thống tích hợp 3 lớp
#### 13.4.1 So sánh với baseline (RF đơn lẻ, PE đơn lẻ, YARA đơn lẻ)
#### 13.4.2 False Positive Rate (FPR) sau khi áp dụng whitelist
#### 13.4.3 Hiệu năng: thời gian quét (giây/file), mức sử dụng CPU/RAM

### 13.5 Kịch bản kiểm thử thực tế
#### 13.5.1 Kịch bản 1: file WannaCry đã biết — verdict `wannacry`, YARA match
#### 13.5.2 Kịch bản 2: file WannaCry bị pack UPX — ML + PE vẫn phát hiện
#### 13.5.3 Kịch bản 3: quét thư mục hỗn hợp (benign, suspicious, wannacry)
#### 13.5.4 Kịch bản 4: Coverage test suite — 117 tests, độ phủ 85%

---

## CHƯƠNG 14: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

### 14.1 Tổng kết kết quả đạt được
#### 14.1.1 Đối chiếu mục tiêu đề ra và kết quả thực tế
#### 14.1.2 Đóng góp: kiến trúc 3 lớp kết hợp, bộ YARA rules 7 rule đặc thù WannaCry
#### 14.1.3 Bài học kinh nghiệm từ quá trình triển khai

### 14.2 Hạn chế hiện tại
#### 14.2.1 Dataset tổng hợp — chưa dùng mẫu mã độc thật
#### 14.2.2 Chỉ phân tích tĩnh — chưa có sandbox/giám sát hành vi
#### 14.2.3 Giới hạn ở WannaCry — chưa tổng quát hóa sang ransomware khác

### 14.3 Hướng phát triển tương lai
#### 14.3.1 Thu thập mẫu thật từ MalwareBazaar / VirusTotal để retrain
#### 14.3.2 Tích hợp phân tích động (sandbox) bổ sung phân tích tĩnh
#### 14.3.3 Mở rộng YARA rules và ML model sang các họ ransomware khác (LockBit, Ryuk)
#### 14.3.4 Triển khai real-time monitoring với `watchdog` library

---

## TÀI LIỆU THAM KHẢO

1. MITRE ATT&CK S0366 — WannaCry: https://attack.mitre.org/software/S0366/
2. US-CERT Alert TA17-132A: https://www.cisa.gov/uscert/ncas/alerts/TA17-132A
3. Microsoft Security Blog — WannaCrypt Ransomware Worm (May 2017)
4. MalwareTech — How to Accidentally Stop a Global Cyber Attack (Killswitch)
5. Breiman, L. (2001). Random Forests. *Machine Learning*, 45, 5–32.
6. Chawla, N.V. et al. (2002). SMOTE. *JAIR*, 16, 321–357.
7. YARA Documentation v4.x — https://yara.readthedocs.io
8. scikit-learn — Pedregosa et al., JMLR 12, 2825–2830 (2011)
9. VirusFamily PE Format — Microsoft PE/COFF Specification

---
*Tài liệu bám sát mã nguồn `wannacry-detector-lite` — 05/2026*
