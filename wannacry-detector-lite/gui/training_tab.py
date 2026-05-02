"""Tab Huấn Luyện — chọn dataset và huấn luyện mô hình."""

import threading
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk


class TrainingTab(ctk.CTkFrame):
    """Tab huấn luyện mô hình ML."""

    def __init__(self, master) -> None:
        super().__init__(master)
        self._build_ui()

    def _build_ui(self) -> None:
        """Xây dựng UI tab huấn luyện."""
        header = ctk.CTkLabel(
            self,
            text="Huấn Luyện Mô Hình",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        header.pack(pady=(15, 10))

        dataset_frame = ctk.CTkFrame(self)
        dataset_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(dataset_frame, text="Dataset CSV:", font=ctk.CTkFont(size=13)).pack(
            side="left", padx=(10, 5), pady=10
        )
        self.dataset_entry = ctk.CTkEntry(
            dataset_frame, placeholder_text="datasets/wannacry_lite.csv"
        )
        self.dataset_entry.pack(side="left", fill="x", expand=True, padx=5, pady=10)
        self.dataset_entry.insert(0, "datasets/wannacry_lite.csv")
        browse_btn = ctk.CTkButton(
            dataset_frame, text="Chọn...", width=70, command=self._browse_dataset
        )
        browse_btn.pack(side="left", padx=(5, 10), pady=10)

        params_frame = ctk.CTkFrame(self)
        params_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(params_frame, text="Tham Số", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=10, pady=(8, 5)
        )

        params_inner = ctk.CTkFrame(params_frame, fg_color="transparent")
        params_inner.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(params_inner, text="Số cây:").pack(side="left", padx=(0, 5))
        self.estimators_var = ctk.StringVar(value="200")
        ctk.CTkEntry(params_inner, width=80, textvariable=self.estimators_var).pack(side="left", padx=5)

        ctk.CTkLabel(params_inner, text="Độ sâu:").pack(side="left", padx=(20, 5))
        self.depth_var = ctk.StringVar(value="20")
        ctk.CTkEntry(params_inner, width=80, textvariable=self.depth_var).pack(side="left", padx=5)

        ctk.CTkLabel(params_inner, text="Seed:").pack(side="left", padx=(20, 5))
        self.seed_var = ctk.StringVar(value="42")
        ctk.CTkEntry(params_inner, width=80, textvariable=self.seed_var).pack(side="left", padx=5)

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=10)
        self.train_btn = ctk.CTkButton(
            btn_frame,
            text="Bắt Đầu Huấn Luyện",
            width=160,
            command=self._start_training,
        )
        self.train_btn.pack(side="left", padx=5)

        gen_dataset_btn = ctk.CTkButton(
            btn_frame,
            text="Tạo Dataset Giả Lập",
            width=200,
            command=self._generate_dataset,
        )
        gen_dataset_btn.pack(side="left", padx=5)

        self.progress_bar = ctk.CTkProgressBar(self)
        self.progress_bar.pack(fill="x", padx=15, pady=5)
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(
            self, text="Sẵn sàng huấn luyện", font=ctk.CTkFont(size=12), text_color="gray"
        )
        self.status_label.pack(pady=(0, 5))

        output_frame = ctk.CTkFrame(self)
        output_frame.pack(fill="both", expand=True, padx=15, pady=(5, 10))
        self.output_text = ctk.CTkTextbox(output_frame, wrap="word")
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.output_text.insert("1.0", "Kết quả huấn luyện sẽ hiển thị ở đây...\n")

    def _browse_dataset(self) -> None:
        """Mở hộp thoại chọn file dataset CSV."""
        path = filedialog.askopenfilename(
            title="Chọn dataset CSV",
            filetypes=[("CSV files", "*.csv"), ("Tất cả file", "*.*")],
        )
        if path:
            self.dataset_entry.delete(0, "end")
            self.dataset_entry.insert(0, path)

    def _generate_dataset(self) -> None:
        """Tạo dataset giả lập trong luồng nền."""
        self.train_btn.configure(state="disabled")
        self.status_label.configure(text="Đang tạo dataset...", text_color="yellow")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", "Đang tạo dataset giả lập...\n")

        def run() -> None:
            try:
                import sys
                from io import StringIO

                from scripts.build_wannacry_dataset import build_dataset, save_dataset

                old_stdout = sys.stdout
                old_stderr = sys.stderr
                captured = StringIO()
                sys.stdout = captured
                sys.stderr = captured

                rows = build_dataset(
                    wannacry_count=500,
                    benign_count=2000,
                    benign_dir=None,
                )
                save_dataset(rows, Path("datasets/wannacry_lite.csv"))

                sys.stdout = old_stdout
                sys.stderr = old_stderr

                self.after(0, lambda: self.output_text.insert("end", captured.getvalue()))
                self.after(0, lambda: self.status_label.configure(
                    text="Đã tạo dataset: datasets/wannacry_lite.csv", text_color="green"
                ))
                self.after(0, lambda: self.progress_bar.set(1.0))
            except Exception as exc:
                err_msg = str(exc)
                self.after(0, lambda m=err_msg: self.output_text.insert("end", f"LỖI: {m}\n"))
                self.after(0, lambda m=err_msg: self.status_label.configure(
                    text=f"Lỗi: {m}", text_color="red"
                ))
            finally:
                self.after(0, lambda: self.train_btn.configure(state="normal"))

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

    def _start_training(self) -> None:
        """Bắt đầu huấn luyện trong luồng nền."""
        self.train_btn.configure(state="disabled")
        self.progress_bar.set(0.1)
        self.status_label.configure(text="Đang huấn luyện...", text_color="yellow")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", "Bắt đầu huấn luyện...\n")

        def run() -> None:
            try:
                from train_model import train_model as do_train

                dataset = Path(self.dataset_entry.get().strip())
                n_estimators = int(self.estimators_var.get())
                max_depth = int(self.depth_var.get())
                seed = int(self.seed_var.get())

                self.after(0, lambda: self.progress_bar.set(0.3))
                self.after(0, lambda: self.output_text.insert("end", "Đang tải dataset...\n"))

                do_train(
                    dataset_path=dataset,
                    output_path=Path("models/wannacry_rf.pkl"),
                    n_estimators=n_estimators,
                    max_depth=max_depth,
                    seed=seed,
                )

                self.after(0, lambda: self.progress_bar.set(1.0))
                self.after(0, lambda: self.output_text.insert(
                    "end", "\nHuấn luyện hoàn tất! Model đã lưu vào models/wannacry_rf.pkl\n"
                ))
                self.after(0, lambda: self.status_label.configure(
                    text="Huấn luyện hoàn tất — model đã lưu", text_color="green"
                ))
            except FileNotFoundError:
                self.after(0, lambda: self.output_text.insert(
                    "end", "\nLỖI: Không tìm thấy dataset. Hãy tạo dataset trước:\n"
                    "python scripts/build_wannacry_dataset.py\n"
                ))
                self.after(0, lambda: self.status_label.configure(
                    text="Không tìm thấy dataset", text_color="red"
                ))
            except Exception as exc:
                err_msg = str(exc)
                self.after(0, lambda m=err_msg: self.output_text.insert("end", f"\nLỖI: {m}\n"))
                self.after(0, lambda m=err_msg: self.status_label.configure(
                    text=f"Huấn luyện thất bại: {m}", text_color="red"
                ))
            finally:
                self.after(0, lambda: self.train_btn.configure(state="normal"))

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
