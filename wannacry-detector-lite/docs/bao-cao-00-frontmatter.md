# BÁO CÁO BÀI TẬP LỚN

---

**Đề tài:** Nghiên cứu và Xây dựng Công cụ Phát hiện Mã độc WannaCry
dựa trên Học máy, Phân tích PE và YARA Rules

| | |
|---|---|
| **Họ và tên** | Trần Huy Hoàng |
| **Mã sinh viên** | B23DCAT190 |
| **Ngành** | An toàn thông tin |
| **Trường** | Học viện Công nghệ Bưu chính Viễn thông (PTIT) |
| **Năm học** | 2025–2026 |

---

## DANH MỤC TỪ VIẾT TẮT

| STT | Từ viết tắt | Ý nghĩa đầy đủ (Tiếng Anh) | Ngữ cảnh sử dụng |
|-----|-------------|------------------------------|------------------|
| 1 | AES | Advanced Encryption Standard | WannaCry dùng AES-128 mã hóa file nạn nhân |
| 2 | API | Application Programming Interface | Windows API, Crypto API import trong PE |
| 3 | AUC | Area Under the Curve | Diện tích dưới đường ROC — chỉ số đánh giá ML |
| 4 | CLI | Command-Line Interface | Giao diện dòng lệnh `main.py --scan` |
| 5 | CSV | Comma-Separated Values | Định dạng dataset và báo cáo kết quả quét |
| 6 | CVE | Common Vulnerabilities and Exposures | CVE-2017-0144 — lỗ hổng EternalBlue/SMBv1 |
| 7 | DLL | Dynamic-Link Library | File PE dạng thư viện, đối tượng phân tích |
| 8 | EXE | Executable | File thực thi Windows, đối tượng phân tích chính |
| 9 | FN | False Negative | Âm tính giả — mã độc bị bỏ sót (nguy hiểm) |
| 10 | FP | False Positive | Dương tính giả — file lành tính bị cảnh báo nhầm |
| 11 | FPR | False Positive Rate | Tỷ lệ dương tính giả: $FPR = FP/(FP+TN)$ |
| 12 | GUI | Graphical User Interface | Giao diện đồ họa — CustomTkinter |
| 13 | IAT | Import Address Table | Bảng import API trong cấu trúc PE |
| 14 | IOC | Indicator of Compromise | Dấu hiệu thỏa hiệp: mutex, domain, chuỗi đặc trưng |
| 15 | JSON | JavaScript Object Notation | Định dạng config và báo cáo kết quả |
| 16 | MD5 | Message Digest Algorithm 5 | Hàm băm (hệ thống dùng SHA-256 thay thế) |
| 17 | ML | Machine Learning | Học máy — Random Forest engine chính |
| 18 | MITRE | MITRE ATT&CK Framework | Khung chiến thuật tấn công — S0366 WannaCry |
| 19 | MZ | Mark Zbikowski | Magic bytes đầu file PE: `0x4D 0x5A` |
| 20 | NSA | National Security Agency | Cơ quan An ninh Mỹ — nguồn gốc exploit EternalBlue |
| 21 | PE | Portable Executable | Định dạng file thực thi Windows |
| 22 | PDF | Portable Document Format | Định dạng báo cáo xuất ra |
| 23 | PKL | Pickle | Định dạng lưu model scikit-learn (`.pkl`) |
| 24 | PTIT | Posts and Telecommunications Institute of Technology | Học viện Công nghệ Bưu chính Viễn thông |
| 25 | RAM | Random Access Memory | Bộ nhớ truy cập ngẫu nhiên — 32GB DDR5 (thực nghiệm) |
| 26 | RCE | Remote Code Execution | Thực thi mã từ xa — kết quả khai thác EternalBlue |
| 27 | RF | Random Forest | Rừng ngẫu nhiên — thuật toán ML chính của hệ thống |
| 28 | ROC | Receiver Operating Characteristic | Đường cong đánh giá phân loại nhị phân |
| 29 | RSA | Rivest–Shamir–Adleman | Mã hóa bất đối xứng — WannaCry dùng RSA-2048 |
| 30 | SHA | Secure Hash Algorithm | SHA-256 dùng cho whitelist và metadata |
| 31 | SMB | Server Message Block | Giao thức chia sẻ file Windows — vector lây lan WannaCry |
| 32 | SMOTE | Synthetic Minority Over-sampling Technique | Cân bằng dữ liệu huấn luyện |
| 33 | SYS | System Driver | File PE dạng driver, đối tượng phân tích |
| 34 | TN | True Negative | Âm tính thật — file lành tính được nhận diện đúng |
| 35 | TP | True Positive | Dương tính thật — mã độc được phát hiện đúng |
| 36 | URL | Uniform Resource Locator | Địa chỉ URL — killswitch domain của WannaCry |
| 37 | YARA | Yet Another Recursive Acronym | Ngôn ngữ viết rule phát hiện mã độc theo pattern |

---

## MỤC LỤC CHI TIẾT

### DANH MỤC TỪ VIẾT TẮT

### CHƯƠNG 1: TỔNG QUAN VỀ RANSOMWARE VÀ WANNACRY
- [1.1 Khái niệm Ransomware](#11-khái-niệm-ransomware)
  - [1.1.1 Định nghĩa và phân loại](#111-định-nghĩa-và-phân-loại)
  - [1.1.2 Vòng đời tấn công điển hình](#112-vòng-đời-tấn-công-điển-hình)
- [1.2 Ransomware WannaCry](#12-ransomware-wannacry)
  - [1.2.1 Bối cảnh xuất hiện (tháng 5/2017)](#121-bối-cảnh-xuất-hiện-tháng-52017)
  - [1.2.2 Cơ chế hoạt động kỹ thuật](#122-cơ-chế-hoạt-động-kỹ-thuật)
  - [1.2.3 Các IOC đặc trưng](#123-các-ioc-đặc-trưng)
  - [1.2.4 Vector lây lan qua lỗ hổng SMB — EternalBlue](#124-vector-lây-lan-qua-lỗ-hổng-smb--eternalblue-cve-2017-0144)
- [1.3 Lý do chọn đề tài và tính cấp thiết](#13-lý-do-chọn-đề-tài-và-tính-cấp-thiết)

### CHƯƠNG 2: MỤC TIÊU VÀ PHẠM VI NGHIÊN CỨU
- [2.1 Mục tiêu nghiên cứu](#21-mục-tiêu-nghiên-cứu)
  - [2.1.1 Mục tiêu tổng quát](#211-mục-tiêu-tổng-quát)
  - [2.1.2 Mục tiêu cụ thể và các chỉ số đo lường](#212-mục-tiêu-cụ-thể-và-các-chỉ-số-đo-lường)
- [2.2 Phạm vi nghiên cứu](#22-phạm-vi-nghiên-cứu)
  - [2.2.1 Đối tượng phân tích](#221-đối-tượng-phân-tích)
  - [2.2.2 Giới hạn nghiên cứu](#222-giới-hạn-nghiên-cứu)
- [2.3 Phương pháp nghiên cứu tổng quan](#23-phương-pháp-nghiên-cứu-tổng-quan)

### CHƯƠNG 3: CƠ SỞ LÝ THUYẾT
- [3.1 Lý thuyết Entropy Shannon](#31-lý-thuyết-entropy-shannon)
  - [3.1.1 Công thức và ý nghĩa](#311-công-thức-và-ý-nghĩa)
  - [3.1.2 Phân biệt file bình thường vs. file mã hóa](#312-phân-biệt-file-bình-thường-vs-file-mã-hóa)
  - [3.1.3 Entropy theo từng section PE](#313-entropy-theo-từng-section-pe)
- [3.2 Kiểm định Chi-Square phân phối byte](#32-kiểm-định-chi-square-phân-phối-byte)
  - [3.2.1 Công thức](#321-công-thức)
- [3.3 Histogram byte 8 nhóm](#33-histogram-byte-8-nhóm)
- [3.4 Định dạng Portable Executable (PE)](#34-định-dạng-portable-executable-pe)
  - [3.4.1 Cấu trúc file PE](#341-cấu-trúc-file-pe)
  - [3.4.2 Import Address Table (IAT)](#342-import-address-table-iat)
  - [3.4.3 Section đặc thù của WannaCry](#343-section-đặc-thù-của-wannacry)
- [3.5 Thuật toán Random Forest](#35-thuật-toán-random-forest)
  - [3.5.1 Bagging và Decision Tree](#351-bagging-và-decision-tree)
  - [3.5.2 Gini Impurity và Feature Importance](#352-gini-impurity-và-feature-importance)
  - [3.5.3 SMOTE: xử lý mất cân bằng dữ liệu](#353-smote-xử-lý-mất-cân-bằng-dữ-liệu)

### CHƯƠNG 4: KIẾN TRÚC HỆ THỐNG TỔNG THỂ
- [4.1 Triết lý thiết kế đa lớp (Defense-in-Depth)](#41-triết-lý-thiết-kế-đa-lớp-defense-in-depth)
  - [4.1.1 Ưu điểm kết hợp ML + PE + YARA](#411-ưu-điểm-kết-hợp-ml--pe--yara)
  - [4.1.2 Cơ chế dự phòng (Graceful Degradation)](#412-cơ-chế-dự-phòng-graceful-degradation)
- [4.2 Sơ đồ kiến trúc 3 lớp](#42-sơ-đồ-kiến-trúc-3-lớp)
- [4.3 Luồng dữ liệu chi tiết](#43-luồng-dữ-liệu-chi-tiết)
- [4.4 Cấu trúc module dự án](#44-cấu-trúc-module-dự-án)

### CHƯƠNG 5: MODULE TRÍCH XUẤT ĐẶC TRƯNG
- [5.1 Tổng quan 16 đặc trưng](#51-tổng-quan-16-đặc-trưng)
- [5.2 Nhóm đặc trưng Entropy (feature_1–3)](#52-nhóm-đặc-trưng-entropy-feature_13)
- [5.3 Nhóm đặc trưng phân phối byte (feature_4–12)](#53-nhóm-đặc-trưng-phân-phối-byte-feature_412)
- [5.4 Nhóm đặc trưng cấu trúc PE (feature_13–16)](#54-nhóm-đặc-trưng-cấu-trúc-pe-feature_1316)
- [5.5 Danh sách SUSPICIOUS_IMPORTS và lý do chọn lọc](#55-danh-sách-suspicious_imports-và-lý-do-chọn-lọc)
- [5.6 Xử lý ngoại lệ](#56-xử-lý-ngoại-lệ)

### CHƯƠNG 6: ENGINE HỌC MÁY — RANDOM FOREST
- [6.1 Kiến trúc lớp MLEngine](#61-kiến-trúc-lớp-mlengine)
- [6.2 Quy trình dự đoán](#62-quy-trình-dự-đoán)
- [6.3 Quy trình huấn luyện](#63-quy-trình-huấn-luyện)
  - [6.3.1 Tiền xử lý dữ liệu](#631-tiền-xử-lý-dữ-liệu)
  - [6.3.2 Xử lý imbalance với SMOTE](#632-xử-lý-imbalance-với-smote)
  - [6.3.3 Huấn luyện RandomForestClassifier](#633-huấn-luyện-randomforestclassifier)
  - [6.3.4 Đánh giá và lưu model](#634-đánh-giá-và-lưu-model)

### CHƯƠNG 7: PHÂN TÍCH CẤU TRÚC PE (PE ANALYZER)
- [7.1 Lớp PEResult và các trường dữ liệu](#71-lớp-peresult-và-các-trường-dữ-liệu)
- [7.2 Phát hiện Packer](#72-phát-hiện-packer)
- [7.3 Phát hiện WannaCry Section](#73-phát-hiện-wannacry-section)
- [7.4 Công thức tính suspicion_score](#74-công-thức-tính-suspicion_score)

### CHƯƠNG 8: ENGINE YARA RULES
- [8.1 Tổng quan lớp YaraEngine](#81-tổng-quan-lớp-yaraengine)
- [8.2 Bộ 7 YARA Rules — wannacry.yar](#82-bộ-7-yara-rules--wannacryyar)
  - [Rule 1: WannaCry_Strings](#rule-1-wannacry_strings)
  - [Rule 2: WannaCry_Killswitch](#rule-2-wannacry_killswitch-severity-critical)
  - [Rule 3: WannaCry_Mutex](#rule-3-wannacry_mutex)
  - [Rule 4: WannaCry_Crypto_Imports](#rule-4-wannacry_crypto_imports-yêu-cầu-kết-hợp)
  - [Rule 5: WannaCry_Ransom_Note](#rule-5-wannacry_ransom_note)
  - [Rule 6: WannaCry_File_Extension](#rule-6-wannacry_file_extension)
  - [Rule 7: WannaCry_SMB_Exploit](#rule-7-wannacry_smb_exploit-severity-critical)
- [8.3 Điều kiện chung: magic bytes PE](#83-điều-kiện-chung-uint160--0x5a4d-magic-bytes-pe)
- [8.4 Tích hợp vào Pipeline](#84-tích-hợp-vào-pipeline)

### CHƯƠNG 9: CƠ CHẾ KẾT HỢP PHÁN QUYẾT VÀ GIẢM THIỂU FALSE POSITIVE
- [9.1 Hàm _combine_verdict()](#91-hàm-_combine_verdict)
- [9.2 Bảng phán quyết đầy đủ](#92-bảng-phán-quyết-đầy-đủ)
- [9.3 Cơ chế Whitelist (FPReducer)](#93-cơ-chế-whitelist-fpreducer)
- [9.4 Pipeline quét song song](#94-pipeline-quét-song-song)

### CHƯƠNG 10: GIAO DIỆN NGƯỜI DÙNG
- [10.1 Giao diện dòng lệnh CLI](#101-giao-diện-dòng-lệnh-cli)
- [10.2 Giao diện đồ họa GUI (CustomTkinter)](#102-giao-diện-đồ-họa-gui-customtkinter)
- [10.3 Quản lý cấu hình (config_manager.py)](#103-quản-lý-cấu-hình-config_managerpy)

### CHƯƠNG 11: HỆ THỐNG BÁO CÁO
- [11.1 Dataclass ScanResult](#111-dataclass-scanresult)
- [11.2 Báo cáo CSV](#112-báo-cáo-csv)
- [11.3 Báo cáo JSON](#113-báo-cáo-json)
- [11.4 Summary Statistics](#114-summary-statistics)

### CHƯƠNG 12: XÂY DỰNG BỘ DỮ LIỆU THỰC NGHIỆM
- [12.1 Chiến lược xây dựng dataset tổng hợp](#121-chiến-lược-xây-dựng-dataset-tổng-hợp)
- [12.2 Phân phối đặc trưng được mô phỏng](#122-phân-phối-đặc-trưng-được-mô-phỏng)
- [12.3 Cấu trúc file CSV](#123-cấu-trúc-file-csv)
- [12.4 Phân tích thống kê bộ dữ liệu](#124-phân-tích-thống-kê-bộ-dữ-liệu)

### CHƯƠNG 13: KẾT QUẢ THỰC NGHIỆM VÀ ĐÁNH GIÁ
- [13.1 Môi trường thực nghiệm](#131-môi-trường-thực-nghiệm)
- [13.2 Các chỉ số đánh giá](#132-các-chỉ-số-đánh-giá)
  - [13.2.1 Precision, Recall, F1-Score](#1321-precision-recall-f1-score)
  - [13.2.2 Confusion Matrix](#1322-confusion-matrix)
  - [13.2.3 AUC-ROC](#1323-auc-roc)
- [13.3 Kết quả từng lớp phát hiện](#133-kết-quả-từng-lớp-phát-hiện)
  - [13.3.1 ML Engine (Random Forest độc lập)](#1331-ml-engine-random-forest-độc-lập)
  - [13.3.2 PE Analyzer (độc lập)](#1332-pe-analyzer-độc-lập)
  - [13.3.3 YARA Engine (7 rules)](#1333-yara-engine-7-rules)
- [13.4 Kết quả hệ thống tích hợp 3 lớp](#134-kết-quả-hệ-thống-tích-hợp-3-lớp)
- [13.5 Hiệu năng](#135-hiệu-năng)
- [13.6 Kịch bản kiểm thử thực tế](#136-kịch-bản-kiểm-thử-thực-tế)
  - [13.6.1 Kịch bản 1: File WannaCry đã biết](#1361-kịch-bản-1-file-wannacry-đã-biết-yara-match)
  - [13.6.2 Kịch bản 2: File WannaCry bị pack UPX](#1362-kịch-bản-2-file-wannacry-bị-pack-upx)
  - [13.6.3 Kịch bản 3: Quét thư mục hỗn hợp](#1363-kịch-bản-3-quét-thư-mục-hỗn-hợp)
  - [13.6.4 Kịch bản 4: Test suite tự động](#1364-kịch-bản-4-test-suite-tự-động)

### CHƯƠNG 14: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN
- [14.1 Tổng kết kết quả đạt được](#141-tổng-kết-kết-quả-đạt-được)
  - [14.1.1 Đối chiếu mục tiêu](#1411-đối-chiếu-mục-tiêu)
  - [14.1.2 Đóng góp kỹ thuật](#1412-đóng-góp-kỹ-thuật)
  - [14.1.3 Bài học kinh nghiệm](#1413-bài-học-kinh-nghiệm)
- [14.2 Hạn chế hiện tại](#142-hạn-chế-hiện-tại)
- [14.3 Hướng phát triển tương lai](#143-hướng-phát-triển-tương-lai)

### TÀI LIỆU THAM KHẢO

---

> **Ghi chú đọc báo cáo:**
> Nội dung chi tiết được lưu trong các file:
> - `bao-cao-chuong1-3.md` — Chương 1, 2, 3
> - `bao-cao-chuong4-6.md` — Chương 4, 5, 6
> - `bao-cao-chuong7-11.md` — Chương 7, 8, 9, 10, 11
> - `bao-cao-chuong12-14.md` — Chương 12, 13, 14 + Tài liệu tham khảo
