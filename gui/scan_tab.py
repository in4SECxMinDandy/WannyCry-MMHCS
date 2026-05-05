"""Tab Quét File — chọn file, tiến trình, kết quả màu sắc, đánh dấu người dùng (WannaCry & BlackCat)."""

import csv
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core.config_manager import load_config
from core.feature_extractor import NUM_FEATURES, extract_features
from core.logger_setup import get_logger
from core.report_generator import ReportGenerator
from core.scanner import Scanner

logger = get_logger(__name__)

VERDICT_COLORS = {
    "wannacry": ("#FF4444", "#8B0000", "[!!] WANNACRY"),
    "blackcat": ("#FF6600", "#8B3300", "[!!] BLACKCAT"),
    "suspicious": ("#FFA500", "#8B6914", "[?]  NGHI NGỞ"),
    "benign": ("#44BB44", "#006400", "[-]  AN TOÀN"),
    "error": ("#888888", "#555555", "[X]  LỖI"),
}

MARK_OPTIONS = ["Bỏ qua", "An toàn", "Nguy hiểm"]


class ScanTab(ctk.CTkFrame):
    """Tab quét file với đánh dấu mức độ nguy hiểm và học từ người dùng."""

    def __init__(self, master) -> None:
        super().__init__(master)
        self._results = []
        self._scanner = None
        self._on_scan_complete = None
        self._mark_vars: list[ctk.StringVar] = []
        self._mark_widgets: list[ctk.CTkComboBox] = []
        self._build_ui()

    def _build_ui(self) -> None:
        """Xây dựng UI tab quét."""
        header = ctk.CTkLabel(
            self,
            text="Quét File — Phát Hiện WannaCry & BlackCat",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        header.pack(pady=(15, 5))

        # --- Nhập đường dẫn ---
        path_frame = ctk.CTkFrame(self)
        path_frame.pack(fill="x", padx=15, pady=5)

        self.path_entry = ctk.CTkEntry(path_frame, placeholder_text="Chọn file hoặc thư mục để quét...")
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=8)

        ctk.CTkButton(path_frame, text="Chọn...", width=80, command=self._browse).pack(
            side="left", padx=5, pady=8
        )
        ctk.CTkButton(path_frame, text="Quét", width=80, command=self._start_scan).pack(
            side="left", padx=(5, 10), pady=8
        )

        # --- Tiến trình ---
        self.progress_bar = ctk.CTkProgressBar(self)
        self.progress_bar.pack(fill="x", padx=15, pady=5)
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(
            self, text="Sẵn sàng", font=ctk.CTkFont(size=12), text_color="gray"
        )
        self.status_label.pack(pady=(0, 5))

        # --- Bảng tổng quan mức độ nguy hiểm ---
        self.summary_frame = ctk.CTkFrame(self)
        self.summary_frame.pack(fill="x", padx=15, pady=(5, 0))

        self.danger_badge = ctk.CTkLabel(
            self.summary_frame,
            text="TỔNG QUAN: ĐỢI",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="gray",
        )
        self.danger_badge.pack(side="left", padx=15, pady=8)

        self.danger_detail = ctk.CTkLabel(
            self.summary_frame,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="gray",
        )
        self.danger_detail.pack(side="right", padx=15, pady=8)

        # --- Vùng kết quả ---
        self.results_text = ctk.CTkTextbox(self, wrap="none", font=ctk.CTkFont(size=12, family="Consolas"))
        self.results_text.pack(fill="both", expand=True, padx=15, pady=(5, 5))
        self.results_text.insert("1.0", "Kết quả quét sẽ hiển thị ở đây...\n")

        # --- Vùng đánh dấu để học lại ---
        self.feedback_label = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.feedback_label.pack(pady=(5, 0))

        self.feedback_frame = ctk.CTkScrollableFrame(self, height=120)
        self.feedback_frame.pack(fill="x", padx=15, pady=(5, 0))

        self.feed_btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.feed_btn_frame.pack(fill="x", padx=15, pady=(5, 0))

        self.feed_count_label = ctk.CTkLabel(
            self.feed_btn_frame, text="", font=ctk.CTkFont(size=11), text_color="gray"
        )
        self.feed_count_label.pack(side="left", pady=5)

        self.feed_btn = ctk.CTkButton(
            self.feed_btn_frame,
            text="Thêm vào Dataset",
            width=160,
            command=self._feed_to_dataset,
            state="disabled",
        )
        self.feed_btn.pack(side="right", padx=5, pady=5)

    def _browse(self) -> None:
        """Mở hộp thoại chọn thư mục."""
        path = filedialog.askdirectory(title="Chọn thư mục để quét")
        if path:
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, path)

    def _start_scan(self) -> None:
        """Bắt đầu quét trong luồng nền."""
        target = self.path_entry.get().strip()
        if not target:
            self.status_label.configure(text="Vui lòng chọn đường dẫn để quét", text_color="red")
            return

        self.status_label.configure(text="Đang quét...", text_color="yellow")
        self.progress_bar.set(0.1)
        self.danger_badge.configure(text="TỔNG QUAN: ĐANG QUÉT...", text_color="yellow")
        self.danger_detail.configure(text="")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", "Đang quét...\n")
        self._clear_feedback_section()

        thread = threading.Thread(target=self._run_scan, args=(target,), daemon=True)
        thread.start()

    def _run_scan(self, target: str) -> None:
        """Thực thi quét trong luồng nền."""
        try:
            config = load_config(Path("data/config.json"))
            self._scanner = Scanner(config)
            self._results = self._scanner.scan_path(target)

            self.after(0, self._display_results)
            self.after(0, self._build_feedback_section)
            self.after(0, lambda: self.progress_bar.set(1.0))
            self.after(0, lambda: self.status_label.configure(
                text=f"Quét hoàn tất: {len(self._results)} file", text_color="green"
            ))
            if self._on_scan_complete:
                gen = ReportGenerator(Path("reports"))
                summary = gen.generate_summary(self._results)
                self.after(0, lambda s=summary: self._on_scan_complete(s))
        except Exception as exc:
            err_msg = str(exc)
            self.after(0, lambda m=err_msg: self.status_label.configure(
                text=f"Lỗi: {m}", text_color="red"
            ))

    def _display_results(self) -> None:
        """Hiển thị kết quả quét với màu sắc theo mức độ nguy hiểm."""
        self.results_text.delete("1.0", "end")
        self.results_text._textbox.tag_configure("critical", foreground="#FF4444")
        self.results_text._textbox.tag_configure("suspicious", foreground="#FFA500")
        self.results_text._textbox.tag_configure("clean", foreground="#44BB44")
        self.results_text._textbox.tag_configure("header", foreground="#AAAAAA")

        if not self._results:
            self.results_text.insert("1.0", "Không có kết quả.\n")
            self._update_danger_summary(0, 0, 0)
            return

        header_line = f"{'TRẠNG THÁI':15s} {'ML Score':>9s} {'PE Score':>9s} YARA Matches\n"
        self.results_text.insert("end", header_line + "─" * 70 + "\n")

        for r in self._results:
            verdict = r.verdict
            tag_name = "critical" if verdict in ("wannacry", "blackcat") else (
                "suspicious" if verdict == "suspicious" else "clean"
            )
            prefix = VERDICT_COLORS.get(verdict, ("", "", "?"))[2]
            line = (
                f"{prefix:15s} {r.ml_score:>9.3f} {r.pe_suspicion_score:>9.2f} "
                f"{', '.join(r.yara_matches) if r.yara_matches else '-'}\n"
            )
            self.results_text.insert("end", line, tag_name)

        self.results_text.insert("end", "\n" + "─" * 70 + "\n")
        self.results_text.insert("end", "CHI TIẾT FILE\n\n")
        for r in self._results:
            verdict = r.verdict
            tag_name = "critical" if verdict in ("wannacry", "blackcat") else (
                "suspicious" if verdict == "suspicious" else "clean"
            )
            prefix = VERDICT_COLORS.get(verdict, ("", "", "?"))[2]
            fname = Path(r.file_path).name
            detail = (
                f"{prefix:15s} {fname}\n"
                f"               ML: {r.ml_score:.3f}  |  PE: {r.pe_suspicion_score:.2f}  |  "
                f"YARA: {', '.join(r.yara_matches) if r.yara_matches else 'Không có'}\n"
                f"               SHA256: {r.sha256[:16]}...  Kích thước: {r.file_size:,} bytes\n\n"
            )
            self.results_text.insert("end", detail, tag_name)

        gen = ReportGenerator(Path("reports"))
        summary = gen.generate_summary(self._results)
        critical_count = summary["wannacry"] + summary.get("blackcat", 0)
        self._update_danger_summary(critical_count, summary["suspicious"], summary["benign"])

    def _update_danger_summary(self, critical: int, suspicious: int, clean: int) -> None:
        """Cập nhật bảng tổng quan mức độ nguy hiểm."""
        total = critical + suspicious + clean
        if total == 0:
            self.danger_badge.configure(text="TỔNG QUAN: KHÔNG CÓ FILE", text_color="gray")
            self.danger_detail.configure(text="")
            return

        if critical > 0:
            level, color = "NGUY HIỂM", "#FF4444"
        elif suspicious > 0:
            level, color = "CẢNH BÁO", "#FFA500"
        else:
            level, color = "AN TOÀN", "#44BB44"

        self.danger_badge.configure(text=f"TỔNG QUAN: {level}", text_color=color)
        self.danger_detail.configure(
            text=f"Tổng: {total}  |  [!] Nguy hiểm: {critical}  |  [?] Nghi ngờ: {suspicious}  |  [-] An toàn: {clean}"
        )

    # ---------- Phản hồi / học từ người dùng ----------

    def _clear_feedback_section(self) -> None:
        """Xoá vùng đánh dấu."""
        for w in self._mark_widgets:
            w.destroy()
        self._mark_widgets.clear()
        self._mark_vars.clear()
        self.feedback_label.configure(text="")
        self.feed_btn.configure(state="disabled")
        self.feed_count_label.configure(text="")

    def _build_feedback_section(self) -> None:
        """Xây dựng vùng đánh dấu file sau quét để học lại."""
        self._clear_feedback_section()

        if not self._results:
            return

        pe_files = [r for r in self._results if Path(r.file_path).suffix.lower() in {".exe", ".dll", ".sys", ".bin"}]
        if not pe_files:
            self.feedback_label.configure(text="Không có file PE nào để đánh dấu cho việc học lại.")
            return

        self.feedback_label.configure(
            text="Đánh dấu cho AI học (đánh dấu ít nhất 1 file rồi bấm \"Thêm vào Dataset\"):"
        )

        for i, r in enumerate(pe_files):
            row = ctk.CTkFrame(self.feedback_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)

            fname = Path(r.file_path).name
            ctk.CTkLabel(row, text=f"{i+1}. {fname}", font=ctk.CTkFont(size=11), anchor="w").pack(
                side="left", padx=(10, 10)
            )

            var = ctk.StringVar(value="Bỏ qua")
            cb = ctk.CTkComboBox(row, values=MARK_OPTIONS, variable=var, width=110, state="readonly")
            cb.pack(side="right", padx=(5, 10))
            cb.set("Bỏ qua")

            self._mark_vars.append(var)
            self._mark_widgets.append(cb)

        self.feed_btn.configure(state="normal")
        self._update_feed_count()

    def _update_feed_count(self) -> None:
        """Cập nhật số lượng file sẽ được thêm vào dataset."""
        selected = sum(1 for v in self._mark_vars if v.get() in ("An toàn", "Nguy hiểm"))
        if selected > 0:
            self.feed_count_label.configure(text=f"Sẽ thêm {selected} file vào dataset")
        else:
            self.feed_count_label.configure(text="")

    def _feed_to_dataset(self) -> None:
        """Trích xuất đặc trưng từ các file được đánh dấu và thêm vào dataset CSV."""
        selected = sum(1 for v in self._mark_vars if v.get() in ("An toàn", "Nguy hiểm"))
        if selected == 0:
            self.status_label.configure(text="Chưa có file nào được đánh dấu!", text_color="orange")
            return

        an_toan = sum(1 for v in self._mark_vars if v.get() == "An toàn")
        nguy_hiem = sum(1 for v in self._mark_vars if v.get() == "Nguy hiểm")

        ok = messagebox.askyesno(
            title="Xác nhận thêm vào Dataset",
            message=(
                f"Bạn sắp thêm {selected} file vào dataset huấn luyện:\n\n"
                f"  [+] An toàn:  {an_toan} file\n"
                f"  [!] Nguy hiểm: {nguy_hiem} file\n\n"
                f"File sẽ được trích xuất 16 đặc trưng và ghi vào:\n"
                f"datasets/wannacry_lite.csv\n\n"
                f"Sau đó bạn có thể sang tab Huấn Luyện để huấn luyện lại mô hình.\n\n"
                f"Tiếp tục?"
            ),
        )

        if not ok:
            return

        self.feed_btn.configure(state="disabled")
        self.status_label.configure(text="Đang trích xuất đặc trưng...", text_color="yellow")

        def run() -> None:
            dataset_path = Path("datasets/wannacry_lite.csv")
            feature_cols = [f"feature_{i}" for i in range(1, NUM_FEATURES + 1)]
            added = 0
            errors = 0

            pe_files = [
                r for r in self._results
                if Path(r.file_path).suffix.lower() in {".exe", ".dll", ".sys", ".bin"}
            ]

            for _i, (r, var) in enumerate(zip(pe_files, self._mark_vars, strict=False)):
                mark = var.get()
                if mark == "Bỏ qua":
                    continue

                label = "wannacry" if mark == "Nguy hiểm" else "benign"
                file_path = Path(r.file_path)

                try:
                    features = extract_features(file_path)
                    if not features:
                        errors += 1
                        continue

                    row = [features[f"feature_{j}"] for j in range(1, NUM_FEATURES + 1)] + [label]

                    file_exists = dataset_path.exists()
                    with open(dataset_path, "a", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        if not file_exists or dataset_path.stat().st_size == 0:
                            writer.writerow(feature_cols + ["label"])
                        writer.writerow(row)

                    added += 1
                except Exception:
                    errors += 1

            msg = f"Đã thêm {added} file vào dataset"
            if errors:
                msg += f" ({errors} lỗi)"
            msg += "\nVào tab Huấn Luyện để huấn luyện lại mô hình!"

            self.after(0, lambda: self.status_label.configure(text="Đã thêm vào dataset!", text_color="green"))
            self.after(0, lambda: self.feed_count_label.configure(text=msg))
            self.after(0, lambda: self.feed_btn.configure(state="normal"))

            logger.info("Feed to dataset: %d added, %d errors", added, errors)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
