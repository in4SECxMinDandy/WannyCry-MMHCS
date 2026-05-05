# WannaCry Detector Lite 🛡️

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-117%20passed-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)]()

**Công cụ phát hiện mã độc tống tiền WannaCry & BlackCat dành cho nghiên cứu học thuật.**  
*A lightweight ransomware detection tool (WannaCry & BlackCat/ALPHV) for academic research.*

---

## 📖 MỤC LỤC | TABLE OF CONTENTS
- [Tổng quan | Overview](#tổng-quan--overview)
- [Kiến trúc Phát hiện | Detection Architecture](#kiến-trúc-phát-hiện--detection-architecture)
- [Tính năng Hệ thống | System Features](#tính-năng-hệ-thống--system-features)
- [Cài đặt | Installation](#cài-đặt--installation)
- [Hướng dẫn Sử dụng | Usage Guide](#hướng-dẫn-sử-dụng--usage-guide)
  - [Giao diện Dòng lệnh (CLI)](#giao-diện-dòng-lệnh-cli)
  - [Giao diện Đồ họa (GUI)](#giao-diện-đồ-họa-gui)
- [Quy trình Huấn luyện | Training Workflow](#quy-trình-huấn-luyện--training-workflow)
- [Cấu trúc Thư mục | Directory Structure](#cấu-trúc-thư-mục--directory-structure)
- [Đánh giá & Kiểm thử | Testing](#đánh-giá--kiểm-thử--testing)
- [Cảnh báo Học thuật | Academic Disclaimer](#cảnh-báo-học-thuật--academic-disclaimer)
- [Tài liệu Tham khảo | References](#tài-liệu-tham-khảo--references)

---

## 🔍 TỔNG QUAN | OVERVIEW

`ransomware-detector` là một dự án nghiên cứu học thuật tập trung vào việc nhận diện, phân tích và phát hiện các biến thể của mã độc tống tiền **WannaCry** và **BlackCat (ALPHV)**. Dự án ứng dụng kiến trúc phát hiện đa lớp (Multi-layer Detection), kết hợp giữa Phân tích Cấu trúc PE, Phân tích Cú pháp YARA và Học máy (Machine Learning) để tối ưu độ chính xác và giảm thiểu tỷ lệ dương tính giả (False Positives).

Dự án này là phiên bản thu gọn (Lite), tập trung hoàn toàn vào việc phát hiện tĩnh (Static Analysis), loại bỏ các chức năng yêu cầu mạng (như gọi API, truy vấn cơ sở dữ liệu đám mây) hay Honeypot để đảm bảo tốc độ quét nhanh và dễ dàng triển khai trong môi trường cách ly (Air-gapped).

### Họ Ransomware Được Hỗ Trợ
| Họ Ransomware | Mô tả | MITRE ATT&CK |
|---|---|---|
| **WannaCry** | Ransomware worm khai thác EternalBlue (SMB), mã hóa AES-128-CBC | [S0366](https://attack.mitre.org/software/S0366/) |
| **BlackCat (ALPHV)** | RaaS viết bằng Rust, mã hóa AES/ChaCha20+RSA, double extortion | [S1068](https://attack.mitre.org/software/S1068/) |

---

## 🧠 KIẾN TRÚC PHÁT HIỆN | DETECTION ARCHITECTURE

Hệ thống hoạt động với 3 lớp phòng thủ chính để phát hiện ransomware:

1. **Lớp 1: PE Analyzer (Phân tích cấu trúc PE)**
   - Phân tích các hàm API khả nghi đặc trưng cho từng họ ransomware.
   - **WannaCry**: `CryptGenKey`, `InternetOpenUrlA`, `CreateServiceA`...
   - **BlackCat**: `BCryptEncrypt`, `BCryptDecrypt`, `CreateToolhelp32Snapshot`, `TerminateProcess`...
   - Phát hiện binary được biên dịch bằng Rust (đặc trưng của BlackCat).
   - Phát hiện các dấu hiệu file bị mã hóa (Packer) hoặc có cấu trúc bất thường.

2. **Lớp 2: YARA Engine (Phân tích theo mẫu)**
   - Sử dụng tập luật (rules) YARA đặc tả riêng cho **WannaCry** (7 rules) và **BlackCat** (6 rules).
   - **WannaCry**: Tìm kiếm chuỗi `WANACRY!`, Mutex `MsWinZoneMemory`, Killswitch Domain.
   - **BlackCat**: Tìm kiếm Rust module paths (`encrypt_app::`, `locker::core::`), cấu hình JSON nhúng, lệnh xóa shadow copy, UAC bypass, PsExec lateral movement.

3. **Lớp 3: Machine Learning Engine (Học máy)**
   - Sử dụng mô hình Random Forest với **3 lớp phân loại**: `wannacry`, `blackcat`, `benign`.
   - Trích xuất 16 đặc trưng từ file thực thi (Entropy, tỉ lệ Byte, các tham số cấu trúc PE...) để phân loại hành vi một cách chính xác kể cả khi ransomware bị làm mờ (Obfuscated) một phần.

---

## ✨ TÍNH NĂNG HỆ THỐNG | SYSTEM FEATURES

### Những gì ĐƯỢC BAO GỒM
- ✅ Tích hợp cả giao diện Console (CLI) và Đồ họa (GUI) dễ sử dụng.
- ✅ Quét nhanh (Fast Scan) thư mục với báo cáo xuất ra dưới dạng JSON, CSV.
- ✅ Trình tạo bộ dữ liệu giả lập (Synthetic Dataset Builder) dùng cho mục đích đào tạo mô hình.
- ✅ Quy trình huấn luyện Random Forest hoàn chỉnh có khả năng tùy chỉnh tham số.
- ✅ Tỉ lệ bao phủ mã (Code Coverage) đạt mức an toàn >85%.
---

## ⚙️ CÀI ĐẶT | INSTALLATION

### Yêu cầu (Requirements)
- Python 3.10 trở lên.
- Hệ điều hành: Windows 10/11 hoặc Linux.
- *(Lưu ý: Đối với Linux, thư viện `yara-python` có thể yêu cầu cài đặt build tools trước. Ví dụ: `sudo apt-get install libyara-dev`).*

### Các bước cài đặt
```bash
# 1. Clone repository về máy
git clone <repo-url>
cd ransomware-detector

# 2. Tạo môi trường ảo (Khuyến nghị)
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 3. Cài đặt các gói phụ thuộc chính
pip install -r requirements.txt

# 4. (Tuỳ chọn) Cài đặt các gói dành cho nhà phát triển (Testing, Linting)
pip install -r requirements-dev.txt
```

---

## 🚀 HƯỚNG DẪN SỬ DỤNG | USAGE GUIDE

### Giao diện Dòng lệnh (CLI)

Đây là phương thức tương tác mạnh mẽ và linh hoạt nhất, phù hợp để tích hợp vào các hệ thống và kịch bản tự động hóa.

```bash
# Quét toàn bộ một thư mục và in chi tiết quá trình ra console
python main.py --scan "C:\path\to\scan" --verbose

# Quét và lưu kết quả báo cáo ở định dạng CSV và JSON
python main.py --scan "C:\path\to\scan" --report-format json,csv

# Quét với tệp cấu hình tùy chỉnh
python main.py --scan "C:\path\to\scan" --config data/custom_config.json
```

### Giao diện Đồ họa (GUI)

Khởi chạy ứng dụng với giao diện đồ hoạ thân thiện (sử dụng thư viện CustomTkinter):

```bash
python main.py --gui
```
Giao diện bao gồm 3 chức năng (Tabs) chính:
- **Dashboard:** Giám sát trạng thái hoạt động của các Engines và hiển thị thống kê tổng quan của lần quét gần nhất.
- **Scan:** Cho phép chọn file/thư mục qua hộp thoại, tiến hành quét và xem kết quả báo cáo một cách trực quan.
- **Training:** Giao diện cho phép tinh chỉnh các tham số, tạo dataset tổng hợp và huấn luyện mô hình Học máy.

---

## 🤖 QUY TRÌNH HUẤN LUYỆN | TRAINING WORKFLOW

Hệ thống cho phép bạn tự huấn luyện mô hình phân loại với bộ dữ liệu tổng hợp (synthetic data) mà không cần dùng mã độc thật.

```bash
# BƯỚC 1: Tạo bộ dữ liệu tổng hợp (Giả lập đặc trưng WannaCry, BlackCat và File sạch)
python scripts/build_wannacry_dataset.py \
    --wannacry-count 500 \
    --blackcat-count 500 \
    --benign-count 2000 \
    --output datasets/ransomware_lite.csv

# BƯỚC 2: Tiến hành huấn luyện mô hình Random Forest (3 lớp)
python train_model.py \
    --dataset datasets/ransomware_lite.csv \
    --n-estimators 200 \
    --max-depth 20 \
    --model-out models/wannacry_rf.pkl

# BƯỚC 3: Kiểm thử lại trên một thư mục mẫu
python main.py --scan tests/fixtures/
```

---

## 📂 CẤU TRÚC THƯ MỤC | DIRECTORY STRUCTURE

```text
ransomware-detector/
├── main.py                 # Điểm đầu vào (Entrypoint) cho cả CLI và GUI
├── train_model.py          # Script huấn luyện mô hình Machine Learning
├── core/                   # Chứa các module xử lý cốt lõi
│   ├── feature_extractor.py  # Trích xuất 16 đặc trưng (Entropy, PE...)
│   ├── ml_engine.py        # Tải mô hình và suy luận Học máy (3-class)
│   ├── pe_analyzer.py      # Phân tích tĩnh cấu trúc PE (WannaCry + BlackCat)
│   ├── yara_engine.py      # Xử lý quy tắc YARA (multi-file)
│   ├── scanner.py          # Bộ điều phối quy trình quét 3-lớp
│   ├── fp_reducer.py       # Bộ lọc Whitelist (giảm False Positive)
│   ├── config_manager.py   # Đọc và xác thực cấu hình JSON
│   ├── logger_setup.py     # Thiết lập Logging hệ thống
│   └── report_generator.py # Xuất báo cáo kết quả quét (JSON, CSV, PDF)
├── gui/                    # Mã nguồn Giao diện đồ họa CustomTkinter
├── rules/                  # Tập luật YARA
│   ├── wannacry.yar        # 7 rules dành riêng cho WannaCry
│   └── blackcat.yar        # 6 rules dành riêng cho BlackCat/ALPHV
├── scripts/                # Các công cụ hỗ trợ (tạo Dataset, v.v.)
├── tests/                  # Bộ Test nội bộ (đạt 84% coverage, 134 tests)
└── docs/                   # Tài liệu thiết kế chi tiết
```

---

## 🧪 ĐÁNH GIÁ & KIỂM THỬ | TESTING

Dự án được bao phủ kiểm thử cao để đảm bảo tính chính xác và độ ổn định của các engine.

```bash
# Chạy toàn bộ Test suite (yêu cầu thư viện pytest)
pytest

# Chạy Test và in báo cáo độ bao phủ mã (Coverage Report) chi tiết
pytest --cov=core --cov-report=term-missing

# Kiểm tra định dạng code (Linting) bằng Ruff
ruff check .

# Kiểm tra kiểu dữ liệu tĩnh (Static Type Checking)
pyright
```

---

## ⚠️ CẢNH BÁO HỌC THUẬT | ACADEMIC DISCLAIMER

> **CẢNH BÁO: Công cụ này CHỈ DÀNH CHO MỤC ĐÍCH NGHIÊN CỨU HỌC THUẬT.**
> - Chỉ được phép sử dụng công cụ này trên các hệ thống mà bạn có quyền sở hữu hợp pháp hoặc đã được ủy quyền phân tích một cách rõ ràng.
> - Tuyệt đối không sử dụng công cụ, mã nguồn hoặc các tập tin liên quan để phát tán, hỗ trợ, hoặc thực thi mã độc dưới bất kỳ hình thức nào.
> - Tác giả hoàn toàn không chịu trách nhiệm pháp lý đối với mọi hành vi sử dụng sai mục đích hoặc bất kỳ thiệt hại nào phát sinh trực tiếp hoặc gián tiếp từ dự án này.
>
> **WARNING: This tool is for ACADEMIC RESEARCH PURPOSES ONLY.**
> - Only use on systems you own or have explicit permission to analyze.
> - Do not use to distribute or execute malware in any form.
> - The authors assume no liability for misuse or damages.

---

## 📚 TÀI LIỆU THAM KHẢO | REFERENCES

Dự án được xây dựng dựa trên sự phân tích từ các nguồn uy tín:

### WannaCry
- [MITRE ATT&CK — S0366 WannaCry](https://attack.mitre.org/software/S0366/)
- [CISA Alert TA17-132A - Indicators of Compromise](https://www.cisa.gov/uscert/ncas/alerts/TA17-132A)
- [Microsoft: WannaCrypt ransomware worm targets out-of-date systems](https://www.microsoft.com/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/)

### BlackCat (ALPHV)
- [MITRE ATT&CK — S1068 ALPHV/BlackCat](https://attack.mitre.org/software/S1068/)
- [FBI/CISA #StopRansomware: ALPHV BlackCat (AA23-353A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a)
- [SentinelOne: BlackCat Ransomware Technical Analysis](https://www.sentinelone.com/labs/blackcat-ransomware/)

---

## ⚖️ GIẤY PHÉP | LICENSE

Dự án này được phân phối dưới giấy phép **MIT License**. Bạn có thể xem chi tiết tại tệp [LICENSE](LICENSE).

---
*Phát triển bởi PTIT Security Research Lab | WannyCry-MMHCS*
