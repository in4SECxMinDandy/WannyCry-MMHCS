# DANH MỤC TỪ VIẾT TẮT

> **Đề tài:** Hệ thống Phát hiện Ransomware WannaCry dựa trên Học máy, Phân tích PE và YARA Rules
> **Sinh viên:** Trần Huy Hoàng — B23DCAT190 — Ngành An toàn thông tin — PTIT

---

| STT | Từ viết tắt | Ý nghĩa đầy đủ (Tiếng Anh) | Ý nghĩa / Ngữ cảnh sử dụng |
|-----|-------------|-----------------------------|-----------------------------|
| 1 | AI | Artificial Intelligence | Trí tuệ nhân tạo — nền tảng của các engine phát hiện thông minh |
| 2 | AES | Advanced Encryption Standard | Chuẩn mã hóa đối xứng — WannaCry dùng AES-128 mã hóa file nạn nhân |
| 3 | API | Application Programming Interface | Giao diện lập trình ứng dụng — VirusTotal API, Windows API |
| 4 | AUC | Area Under the Curve | Diện tích dưới đường ROC — chỉ số đánh giá mô hình ML |
| 5 | AVG | Average | Giá trị trung bình — thống kê entropy, điểm số phát hiện |
| 6 | C2 | Command and Control | Máy chủ chỉ huy — kênh liên lạc của mã độc với kẻ tấn công |
| 7 | CLI | Command-Line Interface | Giao diện dòng lệnh — `main.py --scan` |
| 8 | CNN | Convolutional Neural Network | Mạng nơ-ron tích chập — phương pháp thay thế cho phân loại mã độc |
| 9 | CPU | Central Processing Unit | Bộ xử lý trung tâm — Intel Core i7-12700H trong môi trường thực nghiệm |
| 10 | CSV | Comma-Separated Values | Định dạng file dữ liệu — xuất báo cáo quét |
| 11 | CTI | Cyber Threat Intelligence | Thông tin tình báo mối đe dọa mạng |
| 12 | CVE | Common Vulnerabilities and Exposures | Danh mục lỗ hổng bảo mật — CVE-2017-0144 (EternalBlue) |
| 13 | DLL | Dynamic-Link Library | Thư viện liên kết động — Windows PE format |
| 14 | DNS | Domain Name System | Hệ thống phân giải tên miền — killswitch domain của WannaCry |
| 15 | DoS | Denial of Service | Tấn công từ chối dịch vụ |
| 16 | EDR | Endpoint Detection and Response | Phát hiện và phản ứng tại điểm cuối |
| 17 | EXE | Executable | File thực thi Windows — định dạng PE chính được phân tích |
| 18 | FN | False Negative | Âm tính giả — mã độc bị bỏ sót |
| 19 | FP | False Positive | Dương tính giả — file lành tính bị phán đoán sai là mã độc |
| 20 | FPR | False Positive Rate | Tỷ lệ dương tính giả — chỉ số quan trọng trong bảo mật |
| 21 | GPU | Graphics Processing Unit | Bộ xử lý đồ họa — NVIDIA RTX 3050Ti trong thực nghiệm |
| 22 | GUI | Graphical User Interface | Giao diện đồ họa người dùng — CustomTkinter |
| 23 | IDS | Intrusion Detection System | Hệ thống phát hiện xâm nhập |
| 24 | IOC | Indicator of Compromise | Chỉ số thỏa hiệp — mutex, domain killswitch, chuỗi đặc trưng WannaCry |
| 25 | IP | Internet Protocol | Giao thức mạng — giám sát kết nối C2 |
| 26 | JSON | JavaScript Object Notation | Định dạng dữ liệu cấu trúc — file config, báo cáo kết quả |
| 27 | KNN | K-Nearest Neighbors | Thuật toán phân loại láng giềng gần nhất — so sánh với RF |
| 28 | LR | Logistic Regression | Hồi quy logistic — baseline model |
| 29 | MD5 | Message Digest Algorithm 5 | Hàm băm — whitelist file hợp lệ |
| 30 | MITRE | MITRE ATT&CK Framework | Khung chiến thuật kỹ thuật tấn công — S0366 WannaCry |
| 31 | ML | Machine Learning | Học máy — Random Forest engine phát hiện chính |
| 32 | MZ | Mark Zbikowski | Magic bytes header của file PE (`4D 5A`) |
| 33 | NSA | National Security Agency | Cơ quan An ninh Quốc gia Mỹ — EternalBlue xuất phát từ NSA |
| 34 | PE | Portable Executable | Định dạng file thực thi Windows — đối tượng phân tích chính |
| 35 | PDF | Portable Document Format | Định dạng báo cáo — xuất kết quả phân tích |
| 36 | PID | Process Identifier | Định danh tiến trình — giám sát hành vi |
| 37 | RAM | Random Access Memory | Bộ nhớ truy cập ngẫu nhiên — 32GB DDR5 trong thực nghiệm |
| 38 | RF | Random Forest | Rừng ngẫu nhiên — thuật toán ML chính của hệ thống |
| 39 | ROC | Receiver Operating Characteristic | Đường đặc tính vận hành — đánh giá phân loại nhị phân |
| 40 | RSA | Rivest–Shamir–Adleman | Mã hóa bất đối xứng — WannaCry dùng RSA-2048 bảo vệ AES key |
| 41 | SHA | Secure Hash Algorithm | Thuật toán băm bảo mật — SHA-256 cho whitelist |
| 42 | SMB | Server Message Block | Giao thức chia sẻ file Windows — vector lây lan của WannaCry |
| 43 | SMOTE | Synthetic Minority Over-sampling Technique | Kỹ thuật cân bằng dữ liệu — xử lý mất cân bằng nhãn |
| 44 | SVM | Support Vector Machine | Máy vectơ hỗ trợ — phương pháp so sánh |
| 45 | TA | Threat Actor | Tác nhân đe dọa — nhóm Lazarus liên quan WannaCry |
| 46 | TN | True Negative | Âm tính thật — file lành tính được nhận diện đúng |
| 47 | TP | True Positive | Dương tính thật — mã độc được phát hiện đúng |
| 48 | TTY | Teletype | Terminal / console — công cụ thực nghiệm |
| 49 | URL | Uniform Resource Locator | Địa chỉ tài nguyên — killswitch URL của WannaCry |
| 50 | VT | VirusTotal | Nền tảng phân tích mã độc đa engine — tích hợp API |
| 51 | YARA | Yet Another Recursive Acronym | Ngôn ngữ viết rules phát hiện mã độc theo pattern |
| 52 | XGBoost | eXtreme Gradient Boosting | Thuật toán boosting — so sánh hiệu năng với RF |

---
*Cập nhật: 05/2026 — Trần Huy Hoàng B23DCAT190*
