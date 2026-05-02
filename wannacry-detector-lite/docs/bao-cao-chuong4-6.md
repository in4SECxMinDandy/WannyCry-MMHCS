## CHƯƠNG 4: KIẾN TRÚC HỆ THỐNG TỔNG THỂ

### 4.1 Triết lý thiết kế đa lớp (Defense-in-Depth)

#### 4.1.1 Ưu điểm kết hợp ML + PE + YARA

Mỗi phương pháp phát hiện đơn lẻ đều có điểm yếu riêng:

| Phương pháp | Điểm mạnh | Điểm yếu |
|-------------|-----------|----------|
| **ML thuần túy** | Tổng quát hóa tốt, phát hiện biến thể | Cần nhiều dữ liệu huấn luyện, black-box |
| **PE Analysis thuần túy** | Không cần training, giải thích được | Chỉ dựa trên cấu trúc, dễ bị bypass |
| **YARA thuần túy** | Chính xác 100% với IOC đã biết | Không phát hiện biến thể mới, cần cập nhật liên tục |

Kiến trúc 3 lớp của dự án kết hợp điểm mạnh của cả ba: YARA xử lý các trường hợp có IOC rõ ràng với độ chắc chắn tuyệt đối; ML phát hiện các mẫu chưa thấy; PE Analyzer cung cấp bằng chứng cấu trúc bổ sung.

#### 4.1.2 Cơ chế dự phòng (Graceful Degradation)

Hệ thống được thiết kế để vẫn hoạt động ngay cả khi một lớp không khả dụng. Trong `scanner.py`:

```python
if model_path.exists():
    self.ml_engine = MLEngine(...)   # ML layer: tùy chọn
if rules_path.exists():
    self.yara_engine = YaraEngine(...)  # YARA layer: tùy chọn
# PE layer: luôn hoạt động (không cần file bên ngoài)
```

Nếu chưa train model, hệ thống vẫn chạy với PE Analyzer + YARA. Đây là thiết kế quan trọng cho môi trường triển khai thực tế.

### 4.2 Sơ đồ kiến trúc 3 lớp

```
                    ┌─────────────────┐
                    │   User Input    │
                    │  (CLI / GUI)    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Scanner.scan_  │
                    │  path()         │
                    └────────┬────────┘
                             │
              ┌──────────────▼──────────────┐
              │    _walk_directory()         │
              │  Lọc: extension, size,       │
              │  whitelist                   │
              └──────────────┬──────────────┘
                             │ files[]
              ┌──────────────▼──────────────┐
              │   ThreadPoolExecutor         │
              │   max_workers = 4            │
              └──┬───────────┬───────────┬──┘
                 │           │           │
        ┌────────▼──┐ ┌──────▼────┐ ┌───▼──────┐
        │ ML Engine │ │PE Analyzer│ │YARA Engine│
        │ RF model  │ │ pefile    │ │wannacry   │
        │ 16 feats  │ │ sections  │ │.yar rules │
        └────────┬──┘ └──────┬────┘ └───┬──────┘
                 │           │           │
        ml_score  pe_score    yara_matches
                 │           │           │
              ┌──▼───────────▼───────────▼──┐
              │      _combine_verdict()      │
              │   wannacry / suspicious /    │
              │   benign                     │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │     ReportGenerator          │
              │   CSV / JSON / PDF           │
              └─────────────────────────────┘
```

### 4.3 Luồng dữ liệu chi tiết

Với mỗi file, phương thức `_analyze_file()` thực hiện tuần tự:

1. **Thu thập metadata:** Kích thước file, SHA-256 hash.
2. **ML layer:** `extract_features()` → `ml_engine.predict()` → `(ml_label, ml_score)`.
3. **PE layer:** `pe_analyzer.analyze()` → `pe_result.suspicion_score`.
4. **YARA layer:** `yara_engine.scan_file()` → `[yara_matches]`.
5. **Verdict Combiner:** `_combine_verdict()` → verdict cuối cùng.
6. **Trả về:** `ScanResult` object với đầy đủ thông tin.

### 4.4 Cấu trúc module dự án

```
wannacry-detector-lite/
├── main.py                    # CLI entrypoint + GUI launcher
├── train_model.py             # Huấn luyện Random Forest
├── core/
│   ├── feature_extractor.py   # 16 đặc trưng PE/entropy
│   ├── ml_engine.py           # Loader + predictor
│   ├── pe_analyzer.py         # Phân tích cấu trúc PE
│   ├── yara_engine.py         # Wrapper yara-python
│   ├── scanner.py             # Pipeline 3 lớp
│   ├── fp_reducer.py          # Whitelist
│   ├── config_manager.py      # JSON config
│   ├── logger_setup.py        # Centralized logging
│   ├── report_generator.py    # CSV + JSON
│   └── pdf_reporter.py        # PDF (tuỳ chọn)
├── rules/wannacry.yar         # 7 YARA rules
├── gui/                       # CustomTkinter GUI
├── scripts/                   # Dataset builder
├── tests/                     # 117 test cases
├── datasets/                  # CSV training data
├── models/                    # Trained .pkl files
└── reports/                   # Output reports
```

---

## CHƯƠNG 5: MODULE TRÍCH XUẤT ĐẶC TRƯNG

### 5.1 Tổng quan 16 đặc trưng

Module `feature_extractor.py` là nền tảng của toàn bộ hệ thống ML. Nó trích xuất 16 đặc trưng số học từ file PE binary:

| Feature | Tên | Nhóm | Mô tả |
|---------|-----|------|-------|
| feature_1 | entropy_full | Entropy | Entropy Shannon toàn bộ file |
| feature_2 | entropy_text | Entropy | Entropy section `.text` |
| feature_3 | entropy_data | Entropy | Entropy section `.data` |
| feature_4 | chi_square | Phân phối | Thống kê $\chi^2$ phân phối byte |
| feature_5 | hist_bin_0_31 | Histogram | Tần suất byte 0–31 |
| feature_6 | hist_bin_32_63 | Histogram | Tần suất byte 32–63 |
| feature_7 | hist_bin_64_95 | Histogram | Tần suất byte 64–95 |
| feature_8 | hist_bin_96_127 | Histogram | Tần suất byte 96–127 |
| feature_9 | hist_bin_128_159 | Histogram | Tần suất byte 128–159 |
| feature_10 | hist_bin_160_191 | Histogram | Tần suất byte 160–191 |
| feature_11 | hist_bin_192_223 | Histogram | Tần suất byte 192–223 |
| feature_12 | hist_bin_224_255 | Histogram | Tần suất byte 224–255 |
| feature_13 | file_size_log | Cấu trúc PE | $\log_2(\text{file\_size})$ |
| feature_14 | num_sections | Cấu trúc PE | Số PE sections |
| feature_15 | exec_ratio | Cấu trúc PE | Tỷ lệ byte trong executable sections |
| feature_16 | suspicious_imports | Cấu trúc PE | Số lượng suspicious API imports |

### 5.2 Nhóm đặc trưng Entropy (feature_1–3)

Ba đặc trưng entropy cung cấp góc nhìn đa chiều:
- `entropy_full`: Cho biết toàn bộ file có bị mã hóa/nén không.
- `entropy_text`: Section `.text` chứa code — entropy cao bất thường gợi ý obfuscation.
- `entropy_data`: Section `.data` entropy cao gợi ý chứa payload mã hóa nhúng.

Nếu một section không tồn tại trong file (ví dụ file bị pack không có `.text` rõ ràng), giá trị mặc định là `0.0`.

### 5.3 Nhóm đặc trưng phân phối byte (feature_4–12)

`chi_square` (feature_4) là bổ sung quan trọng cho entropy: trong khi entropy chỉ đo mức "bất ngờ" tổng thể, chi-square đo xem phân phối có đều hay không. Một file mã hóa tốt (AES) sẽ có $\chi^2$ gần 0 **và** entropy gần 8.

8 bin histogram (feature_5–12) capture hình dạng phân phối byte chi tiết hơn: file lành tính thường có bin_0 cao (nhiều null bytes trong PE header padding) và bin_2-3 cao (ASCII printable chars trong strings), trong khi WannaCry có phân phối phẳng hơn.

### 5.4 Nhóm đặc trưng cấu trúc PE (feature_13–16)

- **`file_size_log`:** Dùng log thay vì giá trị tuyệt đối để tránh dominance của outlier lớn. $\log_2(100MB) \approx 26.5$.
- **`num_sections`:** WannaCry thường có ít sections hơn file exe bình thường (sau khi bị pack).
- **`exec_ratio`:** Tỷ lệ byte trong sections có flag `IMAGE_SCN_MEM_EXECUTE (0x20000000)`. File bị pack thường có exec_ratio cao bất thường vì toàn bộ code nằm trong một section.
- **`suspicious_imports`:** Đếm số lượng API từ danh sách `SUSPICIOUS_IMPORTS` (14 API):

```python
SUSPICIOUS_IMPORTS = {
    "CryptEncrypt", "CryptDecrypt", "CryptGenRandom", "CryptAcquireContextW",
    "FindFirstFileW", "FindNextFileW", "MoveFileExW",
    "InternetOpenA", "InternetOpenUrlA", "InternetReadFile",
    "WinExec", "ShellExecuteA", "CreateRemoteThread", "WriteProcessMemory",
}
```

### 5.5 Xử lý ngoại lệ

Hàm `extract_features()` trả về `None` trong các trường hợp:
- File < 64 bytes (quá nhỏ để là file PE hợp lệ).
- `pefile.PEFormatError`: File không phải định dạng PE.
- `OSError/PermissionError`: Không có quyền đọc file.

Khi `extract_features()` trả về `None`, ML layer bỏ qua và chỉ PE Analyzer + YARA hoạt động.

---

## CHƯƠNG 6: ENGINE HỌC MÁY — RANDOM FOREST

### 6.1 Kiến trúc lớp MLEngine

Lớp `MLEngine` trong `ml_engine.py` đóng gói toàn bộ logic inference:

```python
class MLEngine:
    def __init__(self, model_path: Path, threshold: float = 0.7):
        self.model_path = Path(model_path)
        self.threshold = threshold
        self._model = self._load_model()  # joblib.load(.pkl)
```

Ngưỡng mặc định `threshold = 0.7` có nghĩa: chỉ khi xác suất WannaCry ≥ 70% mới gán nhãn `wannacry`. Ngưỡng này có thể cấu hình qua `config.json`.

### 6.2 Quy trình dự đoán

Phương thức `predict()` thực hiện:

```python
def predict(self, features: dict[str, float]) -> tuple[str, float]:
    arr = np.array([features_to_array(features)], dtype=np.float32)
    proba = self._model.predict_proba(arr)[0]
    # Tìm index class "wannacry"
    wannacry_idx = ...
    score = float(proba[wannacry_idx])
    label = "wannacry" if score >= self.threshold else "benign"
    return label, score
```

Việc sử dụng `predict_proba()` thay vì `predict()` cho phép lấy xác suất liên tục, phục vụ cho logic `_combine_verdict()` — ví dụ phân biệt `suspicious` (score cao nhưng chưa đến threshold) với `benign`.

### 6.3 Quy trình huấn luyện

#### 6.3.1 Tiền xử lý dữ liệu

```python
df = pd.read_csv(dataset_path)
X = df[FEATURE_COLS].fillna(0).values.astype(np.float32)
y = np.where(df["label"].values == "wannacry", 1, 0)
```

Label được encode thành binary: `wannacry=1`, `benign=0`.

#### 6.3.2 Xử lý imbalance với SMOTE

```python
imbalance_ratio = max(y.sum(), 1) / max((len(y) - y.sum()), 1)
if imbalance_ratio > 0.2:
    smote = SMOTE(random_state=42, k_neighbors=min(5, int(y.sum()) - 1))
    X, y = smote.fit_resample(X, y)
```

Ngưỡng `0.2` có nghĩa: nếu tỷ lệ wannacry/benign < 20%, áp dụng SMOTE.

#### 6.3.3 Huấn luyện RandomForestClassifier

```python
model = RandomForestClassifier(
    n_estimators=200,      # 200 cây
    max_depth=20,          # Độ sâu tối đa
    class_weight="balanced",  # Tự động cân bằng class weight
    random_state=42,
    n_jobs=-1,             # Dùng tất cả CPU cores
)
model.fit(X_train, y_train)
```

Tham số `class_weight="balanced"` là lớp bảo vệ thứ hai sau SMOTE — tự động điều chỉnh trọng số mẫu tỷ lệ nghịch với tần suất class.

#### 6.3.4 Đánh giá và lưu model

```python
# Classification report
logger.info("\n%s", classification_report(y_test, y_pred,
    target_names=["benign", "wannacry"]))
# Cross-validation
cv_scores = cross_val_score(model, X, y, cv=5)
# Lưu model
joblib.dump(model, output_path)
```

Top 5 Feature Importance được log để người dùng hiểu mô hình dựa vào đặc trưng nào nhiều nhất.
