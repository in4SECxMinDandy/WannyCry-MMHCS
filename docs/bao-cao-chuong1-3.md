# BÁO CÁO BÀI TẬP LỚN

**Đề tài:** Nghiên cứu và Xây dựng Công cụ Phát hiện Mã độc WannaCry dựa trên Học máy, Phân tích PE và YARA Rules
**Sinh viên:** Trần Huy Hoàng | **Mã SV:** B23DCAT190 | **Ngành:** An toàn thông tin | **Trường:** PTIT

---

## CHƯƠNG 1: TỔNG QUAN VỀ RANSOMWARE VÀ WANNACRY

### 1.1 Khái niệm Ransomware

#### 1.1.1 Định nghĩa và phân loại

Ransomware (mã độc tống tiền) là một dạng phần mềm độc hại (malware) mã hóa dữ liệu của nạn nhân hoặc khóa quyền truy cập hệ thống, sau đó yêu cầu nạn nhân trả tiền chuộc — thường bằng tiền điện tử (Bitcoin, Monero) — để nhận lại khóa giải mã. Theo định nghĩa của CISA (Cybersecurity and Infrastructure Security Agency), ransomware là "một loại phần mềm độc hại ngày càng phổ biến, mã hóa các tập tin của nạn nhân và yêu cầu thanh toán để phục hồi quyền truy cập."

Ransomware được phân loại theo cơ chế tống tiền thành hai nhóm chính:

| Loại | Mô tả | Ví dụ |
|------|-------|-------|
| **Crypto Ransomware** | Mã hóa file dữ liệu, giữ nguyên hệ điều hành | WannaCry, REvil, LockBit |
| **Locker Ransomware** | Khóa toàn bộ giao diện hệ thống, không cho truy cập | Police Ransomware, WinLock |

WannaCry thuộc nhóm Crypto Ransomware, sử dụng kết hợp AES-128 để mã hóa nội dung file và RSA-2048 để bảo vệ AES key — đảm bảo nạn nhân không thể tự giải mã mà không có private key của kẻ tấn công.

#### 1.1.2 Vòng đời tấn công điển hình

Một cuộc tấn công ransomware điển hình trải qua các giai đoạn sau:

1. **Xâm nhập ban đầu (Initial Access):** Qua email phishing, khai thác lỗ hổng, hoặc RDP brute-force.
2. **Thực thi (Execution):** Mã độc được chạy, thường qua PowerShell hoặc file PE độc lập.
3. **Duy trì bền vững (Persistence):** Ghi vào registry, tạo scheduled task.
4. **Leo thang đặc quyền (Privilege Escalation):** Chiếm quyền SYSTEM để truy cập toàn bộ file.
5. **Lây lan nội mạng (Lateral Movement):** Quét mạng LAN tìm máy chủ dễ tổn thương.
6. **Mã hóa dữ liệu (Impact):** Mã hóa file theo danh sách phần mở rộng mục tiêu.
7. **Tống tiền (Extortion):** Thả file ransom note hướng dẫn thanh toán.

### 1.2 Ransomware WannaCry

#### 1.2.1 Bối cảnh xuất hiện (tháng 5/2017)

Ngày 12 tháng 5 năm 2017, WannaCry bùng phát trên toàn cầu trong một trong những cuộc tấn công mạng lớn nhất lịch sử. Chỉ trong 24 giờ đầu, hơn **230.000 máy tính** tại **150 quốc gia** bị lây nhiễm. Các tổ chức bị ảnh hưởng nghiêm trọng bao gồm Dịch vụ Y tế Quốc gia Anh (NHS), Telefónica (Tây Ban Nha), FedEx, và nhiều cơ quan chính phủ. Thiệt hại kinh tế ước tính lên tới **4–8 tỷ USD** toàn cầu.

Điểm đặc biệt khiến WannaCry nguy hiểm hơn các ransomware trước đó là khả năng **tự lây lan (self-propagating worm)** — không cần tương tác từ người dùng. WannaCry chủ động quét mạng để tìm các máy dễ bị tấn công và tự động lây nhiễm mà không cần phishing hay social engineering.

#### 1.2.2 Cơ chế hoạt động kỹ thuật

Quy trình hoạt động của WannaCry bao gồm các bước kỹ thuật sau:

1. **Khai thác EternalBlue:** WannaCry sử dụng exploit EternalBlue (CVE-2017-0144) nhắm vào lỗ hổng trong giao thức SMBv1 (Server Message Block) của Windows. Exploit này ban đầu được phát triển bởi NSA và bị nhóm Shadow Brokers đánh cắp và công bố vào tháng 4/2017 — chỉ một tháng trước khi WannaCry bùng phát.

2. **Cài backdoor DoublePulsar:** Sau khi khai thác thành công, WannaCry cài kernel-level backdoor DoublePulsar để duy trì quyền truy cập.

3. **Kiểm tra killswitch:** Trước khi mã hóa, WannaCry thực hiện HTTP GET request đến domain: `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`. Nếu domain phản hồi, mã độc **tự kết thúc**. Cơ chế này được nhà nghiên cứu Marcus Hutchins phát hiện và khai thác để ngăn chặn sự lây lan bằng cách đăng ký domain trên.

4. **Mã hóa file:** WannaCry mã hóa hơn 170 loại phần mở rộng file (.doc, .xls, .jpg, .pdf...) bằng AES-128, đổi tên thành `.wncry`. AES key của mỗi file được mã hóa bằng RSA-2048 public key của kẻ tấn công.

5. **Thả ransom note:** Tạo file `@Please_Read_Me@.txt` và `@WanaDecryptor@.exe` yêu cầu 300–600 USD Bitcoin.

#### 1.2.3 Các IOC đặc trưng

WannaCry để lại nhiều Indicator of Compromise (IOC) đặc trưng, đây là cơ sở xây dựng YARA rules trong dự án:

| Loại IOC | Giá trị | Mô tả |
|----------|---------|-------|
| **Mutex** | `MsWinZonesCacheCounterMutexA` | Ngăn chạy nhiều instance |
| **Domain** | `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com` | Killswitch domain |
| **Chuỗi** | `WANACRY!`, `WanaCrypt0r`, `wcry@123` | Chuỗi định danh trong binary |
| **Section PE** | `.wnry`, `.wncry` | Section đặc thù trong file PE |
| **Phần mở rộng** | `.WNCRY`, `.wcry`, `.WNCRYT` | File sau khi bị mã hóa |
| **File** | `tasksche.exe`, `@WanaDecryptor@.exe` | File được tạo ra khi thực thi |

#### 1.2.4 Vector lây lan qua lỗ hổng SMB — EternalBlue (CVE-2017-0144)

CVE-2017-0144 là lỗ hổng tràn bộ đệm (buffer overflow) trong việc xử lý gói tin SMBv1 Transaction2 của Windows. Lỗ hổng cho phép attacker thực thi mã tùy ý (Remote Code Execution — RCE) mà không cần xác thực, chỉ cần port 445/TCP mở và máy chạy SMBv1. Microsoft đã phát hành bản vá MS17-010 vào tháng 3/2017, nhưng nhiều tổ chức chưa cập nhật kịp thời.

### 1.3 Lý do chọn đề tài và tính cấp thiết

WannaCry, dù đã xuất hiện từ 2017, vẫn còn là mối đe dọa thực tế vì:
- Hàng triệu máy tính toàn cầu vẫn chạy Windows XP và SMBv1 không được vá.
- Các biến thể mới vẫn tiếp tục xuất hiện dựa trên mã nguồn gốc.
- Kỹ thuật phân tích WannaCry là nền tảng tốt để học phương pháp phát hiện ransomware nói chung.

Đề tài này xây dựng công cụ phát hiện WannaCry bằng phương pháp kết hợp ba lớp: học máy (Random Forest), phân tích cấu trúc PE, và YARA rules — tạo ra hệ thống có độ chính xác cao và khả năng giải thích được (explainable).

---

## CHƯƠNG 2: MỤC TIÊU VÀ PHẠM VI NGHIÊN CỨU

### 2.1 Mục tiêu nghiên cứu

#### 2.1.1 Mục tiêu tổng quát

Xây dựng một công cụ phần mềm có khả năng phân tích file PE trên Windows và đưa ra phán quyết phân loại: **wannacry** (là mã độc WannaCry), **suspicious** (nghi ngờ), hoặc **benign** (lành tính). Công cụ phải hoạt động trên môi trường Windows, có giao diện CLI và GUI, hỗ trợ quét theo batch và xuất báo cáo.

#### 2.1.2 Mục tiêu cụ thể và các chỉ số đo lường

| Mục tiêu | Chỉ số đo lường | Ngưỡng mục tiêu |
|----------|-----------------|-----------------|
| Độ chính xác phát hiện | F1-Score (class wannacry) | ≥ 0.90 |
| Tỷ lệ phát hiện | Recall | ≥ 0.92 |
| Tỷ lệ cảnh báo giả | False Positive Rate | ≤ 0.05 |
| Thời gian phản hồi | Giây/file (file < 10MB) | ≤ 2s |
| Độ phủ kiểm thử | Test coverage | ≥ 85% |

### 2.2 Phạm vi nghiên cứu

#### 2.2.1 Đối tượng phân tích

Dự án tập trung vào các file **Portable Executable (PE)** trên Windows với phần mở rộng: `.exe`, `.dll`, `.sys`, `.bin`. Đây là định dạng file mà WannaCry sử dụng — bao gồm file thực thi chính (`tasksche.exe`) và các module phụ trợ.

Kích thước file tối đa được xử lý: **100 MB** (cấu hình mặc định trong `config_manager.py`).

#### 2.2.2 Giới hạn nghiên cứu

- **Chỉ phân tích tĩnh (Static Analysis):** Dự án đọc và phân tích nội dung file mà không thực thi. Không có sandbox hay môi trường ảo hóa.
- **Không gọi API bên ngoài:** Không tích hợp VirusTotal, MalwareBazaar trong phiên bản hiện tại.
- **Không real-time monitoring:** Không có watchdog giám sát filesystem liên tục.
- **Dataset tổng hợp:** Do không có mẫu mã độc thật, bộ dữ liệu huấn luyện được tạo tổng hợp (synthetic).

### 2.3 Phương pháp nghiên cứu tổng quan

Nghiên cứu sử dụng phương pháp kết hợp:

1. **Nghiên cứu tài liệu:** Phân tích các báo cáo kỹ thuật về WannaCry (MITRE ATT&CK S0366, CISA TA17-132A), đọc mã nguồn và báo cáo phân tích từ các hãng bảo mật.
2. **Thiết kế hệ thống:** Xây dựng kiến trúc pipeline 3 lớp, mô-đun hóa từng thành phần.
3. **Triển khai và kiểm thử:** Viết code Python, kiểm thử với pytest (117 test cases, độ phủ 85%).
4. **Đánh giá định lượng:** Đo các chỉ số ML (Precision, Recall, F1-Score, Confusion Matrix) trên tập test.

---

## CHƯƠNG 3: CƠ SỞ LÝ THUYẾT

### 3.1 Lý thuyết Entropy Shannon

#### 3.1.1 Công thức và ý nghĩa

Entropy Shannon đo lường mức độ "bất ngờ" hoặc "ngẫu nhiên" của một nguồn thông tin. Với một chuỗi byte, entropy được tính theo công thức:

$$H(X) = -\sum_{i=0}^{255} p_i \log_2 p_i$$

Trong đó $p_i$ là xác suất xuất hiện của byte có giá trị $i$ trong chuỗi dữ liệu. Entropy có giá trị trong khoảng $[0, 8]$ bit/byte.

Trong mã nguồn `feature_extractor.py`, hàm `_shannon_entropy()` được triển khai như sau:

```python
def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counter = Counter(data)
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy
```

#### 3.1.2 Phân biệt file bình thường vs. file mã hóa

| Loại file | Entropy điển hình | Lý do |
|-----------|-------------------|-------|
| File text (.txt) | 4.0 – 5.5 bit/byte | Phân phối ký tự ASCII không đều |
| File thực thi (.exe) bình thường | 5.5 – 6.5 bit/byte | Mix code + data |
| File bị nén (.zip, .gz) | 7.5 – 8.0 bit/byte | Dữ liệu nén gần ngẫu nhiên |
| File bị mã hóa (ransomware) | 7.8 – 8.0 bit/byte | AES output gần hoàn toàn ngẫu nhiên |

WannaCry mã hóa file bằng AES-128 — output của AES có entropy gần 8.0 bit/byte. Đây là dấu hiệu quan trọng phân biệt file WannaCry với file thực thi bình thường.

#### 3.1.3 Entropy theo từng section PE

Dự án tính entropy riêng cho section `.text` (code) và `.data` (dữ liệu):
- Section `.text` của WannaCry thường có entropy cao do chứa code bị obfuscate.
- Section `.data` có entropy đặc biệt cao do chứa dữ liệu mã hóa nhúng trong file.

### 3.2 Kiểm định Chi-Square phân phối byte

#### 3.2.1 Công thức

$$\chi^2 = \sum_{i=0}^{255} \frac{(O_i - E_i)^2}{E_i}$$

Trong đó:
- $O_i$: số lần thực tế xuất hiện của byte có giá trị $i$
- $E_i = \frac{N}{256}$: số lần kỳ vọng nếu phân phối đều (với $N$ là tổng số byte)

File có phân phối byte **đều** (mã hóa/nén tốt) sẽ có $\chi^2$ **thấp** (gần 0). File text hoặc code thực thi có phân phối lệch sẽ có $\chi^2$ **cao**.

```python
def _chi_square(data: bytes) -> float:
    length = len(data)
    expected = length / 256
    counter = Counter(data)
    chi2 = 0.0
    for byte_val in range(256):
        observed = counter.get(byte_val, 0)
        diff = observed - expected
        chi2 += (diff * diff) / expected
    return chi2
```

Đặc trưng `feature_4 = chi_square` là một trong những đặc trưng có **feature importance cao nhất** trong mô hình Random Forest, vì nó phân biệt tốt file mã hóa với file bình thường.

### 3.3 Histogram byte 8 nhóm

Thay vì xét riêng lẻ 256 giá trị byte, dự án nhóm chúng thành 8 bin theo khoảng:

| Bin | Khoảng byte | Ý nghĩa thực tế |
|-----|-------------|-----------------|
| bin_0 | 0–31 | Control characters, null bytes |
| bin_1 | 32–63 | Dấu câu, chữ số |
| bin_2 | 64–95 | Chữ hoa A-Z, ký tự đặc biệt |
| bin_3 | 96–127 | Chữ thường a-z |
| bin_4 | 128–159 | Extended ASCII |
| bin_5 | 160–191 | Extended ASCII |
| bin_6 | 192–223 | High bytes |
| bin_7 | 224–255 | High bytes |

File WannaCry (sau mã hóa AES) có phân phối **gần đều** trên cả 8 bin (~12.5% mỗi bin). File exe bình thường có tỷ lệ cao ở bin_0 (null bytes trong padding) và bin_2–3 (ASCII code).

### 3.4 Định dạng Portable Executable (PE)

#### 3.4.1 Cấu trúc file PE

File PE (Portable Executable) là định dạng file thực thi chuẩn của Windows. Cấu trúc từ đầu file:

```
[DOS Header]   → 64 bytes, bắt đầu bằng "MZ" (0x4D 0x5A)
[DOS Stub]     → Code 16-bit, hiển thị "This program cannot be run in DOS mode"
[PE Signature] → "PE\0\0" (0x50 0x45 0x00 0x00)
[COFF Header]  → Machine type, số sections, timestamp
[Optional Header] → Entry point, image base, subsystem
[Section Table]   → Danh sách các section (.text, .data, .rsrc...)
[Sections]        → Nội dung thực của từng section
```

Magic bytes `MZ` (0x5A4D ở little-endian) là điều kiện đầu tiên trong tất cả 7 YARA rules: `uint16(0) == 0x5A4D`.

#### 3.4.2 Import Address Table (IAT)

IAT chứa danh sách các hàm API Windows mà file PE import từ các DLL. WannaCry import các Crypto API đặc trưng từ `advapi32.dll`: `CryptEncrypt`, `CryptDecrypt`, `CryptGenRandom`, `CryptAcquireContextW` — đây là bằng chứng trực tiếp về hành vi mã hóa.

#### 3.4.3 Section đặc thù của WannaCry

WannaCry có thể chứa section `.wnry` hoặc `.wncry` trong cấu trúc PE — là section chứa module phụ trợ nhúng bên trong. Sự xuất hiện của section này là IOC mạnh (cộng +0.4 điểm trong `pe_analyzer.py`).

### 3.5 Thuật toán Random Forest

#### 3.5.1 Bagging và Decision Tree

Random Forest là ensemble method kết hợp $T$ cây quyết định (Decision Tree) độc lập, mỗi cây được huấn luyện trên một bootstrap sample khác nhau (Bagging). Phán quyết cuối cùng là majority vote:

$$\hat{y} = \text{argmax}_c \sum_{t=1}^{T} \mathbf{1}[h_t(x) = c]$$

Mỗi cây tại mỗi nút phân chia chỉ xét một tập con ngẫu nhiên $\sqrt{p}$ đặc trưng (với $p=16$ đặc trưng), giúp giảm tương quan giữa các cây và tăng tính tổng quát hóa.

#### 3.5.2 Gini Impurity và Feature Importance

Mỗi nút phân chia được chọn để tối thiểu hóa Gini Impurity:

$$Gini(t) = 1 - \sum_{c} p(c|t)^2$$

Feature Importance của đặc trưng $j$ được tính theo mức giảm Gini trung bình qua tất cả các cây và nút sử dụng đặc trưng đó.

#### 3.5.3 SMOTE: xử lý mất cân bằng dữ liệu

Trong thực tế, tỷ lệ file WannaCry so với file lành tính rất nhỏ (imbalanced dataset). SMOTE (Synthetic Minority Over-sampling Technique) tạo ra các mẫu WannaCry tổng hợp mới bằng cách nội suy giữa các mẫu minority class trong không gian đặc trưng:

$$x_{new} = x_i + \lambda \cdot (x_{nn} - x_i), \quad \lambda \in [0, 1]$$

Trong `train_model.py`, SMOTE được kích hoạt tự động khi `imbalance_ratio > 0.2`:

```python
smote = SMOTE(random_state=seed, k_neighbors=min(5, int(y.sum()) - 1))
X, y = smote.fit_resample(X, y)
```
