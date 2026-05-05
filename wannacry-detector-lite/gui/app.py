"""Ransomware Detector Lite — Giao diện chính (WannaCry + BlackCat)."""

import sys
from pathlib import Path

import customtkinter as ctk

from gui.dashboard_tab import DashboardTab
from gui.logs_tab import LogsTab
from gui.scan_tab import ScanTab
from gui.training_tab import TrainingTab


def launch_gui() -> None:
    """Khởi động giao diện CustomTkinter."""
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    app = WannaCryApp()
    app.mainloop()


class WannaCryApp(ctk.CTk):
    """Cửa sổ chính với giao diện sidebar."""

    def __init__(self) -> None:
        super().__init__()

        self.title("Ransomware Detector Lite v1.1 — WannaCry & BlackCat")
        self.geometry("1000x650")
        self.minsize(800, 500)

        icon_path = Path("assets/icon.ico")
        if icon_path.exists():
            try:
                self.iconbitmap(str(icon_path))
            except Exception:
                pass

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        """Xây dựng giao diện sidebar (trái) và nội dung (phải)."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # 1. Khung Sidebar (Bên trái)
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="Ransomware\nDetector Lite",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        # Nút chuyển tab
        self.btn_dashboard = ctk.CTkButton(
            self.sidebar_frame, text="Bảng Điều Khiển",
            command=lambda: self.select_frame("dashboard"),
            fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w"
        )
        self.btn_dashboard.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        self.btn_scan = ctk.CTkButton(
            self.sidebar_frame, text="Quét File",
            command=lambda: self.select_frame("scan"),
            fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w"
        )
        self.btn_scan.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        self.btn_training = ctk.CTkButton(
            self.sidebar_frame, text="Huấn Luyện",
            command=lambda: self.select_frame("training"),
            fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w"
        )
        self.btn_training.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        self.btn_logs = ctk.CTkButton(
            self.sidebar_frame, text="Logs",
            command=lambda: self.select_frame("logs"),
            fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w"
        )
        self.btn_logs.grid(row=4, column=0, padx=10, pady=5, sticky="ew")

        # 2. Khung Nội Dung (Bên phải)
        self.content_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content_frame.grid(row=0, column=1, sticky="nsew")
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)

        # Các tab nội dung
        self.dashboard_tab = DashboardTab(self.content_frame)
        self.scan_tab = ScanTab(self.content_frame)
        self.scan_tab._on_scan_complete = self.dashboard_tab.update_summary
        self.training_tab = TrainingTab(self.content_frame)
        self.logs_tab = LogsTab(self.content_frame)

        # 3. Status Bar
        self.status_bar = ctk.CTkLabel(
            self,
            text="Sẵn sàng | Công cụ nghiên cứu học thuật — sử dụng có trách nhiệm",
            anchor="w",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        self.status_bar.grid(row=1, column=0, columnspan=2, padx=10, pady=(5, 5), sticky="w")

        # Khởi tạo trạng thái ban đầu
        self.select_frame("dashboard")
        self._check_engine_status()

    def select_frame(self, name: str) -> None:
        """Chuyển đổi giữa các frame/tab."""
        # Reset button colors
        default_color = "transparent"
        active_color = ("gray75", "gray25")

        self.btn_dashboard.configure(fg_color=active_color if name == "dashboard" else default_color)
        self.btn_scan.configure(fg_color=active_color if name == "scan" else default_color)
        self.btn_training.configure(fg_color=active_color if name == "training" else default_color)
        self.btn_logs.configure(fg_color=active_color if name == "logs" else default_color)

        # Hide all frames
        self.dashboard_tab.grid_forget()
        self.scan_tab.grid_forget()
        self.training_tab.grid_forget()
        self.logs_tab.grid_forget()

        # Show selected frame
        if name == "dashboard":
            self.dashboard_tab.grid(row=0, column=0, sticky="nsew")
        elif name == "scan":
            self.scan_tab.grid(row=0, column=0, sticky="nsew")
        elif name == "training":
            self.training_tab.grid(row=0, column=0, sticky="nsew")
        elif name == "logs":
            self.logs_tab.grid(row=0, column=0, sticky="nsew")

    def _on_close(self) -> None:
        """Đóng cửa sổ."""
        self.destroy()
        sys.exit(0)

    def _check_engine_status(self) -> None:
        """Kiểm tra trạng thái ML và YARA khi khởi động."""
        model_path = Path("models/wannacry_rf.pkl")
        self.dashboard_tab.update_ml_status(model_path.exists())

        rules_dir = Path("rules")
        rule_files = ["wannacry.yar", "blackcat.yar"]
        total_rules = 0
        all_loaded = True

        for rule_file in rule_files:
            rule_path = rules_dir / rule_file
            if rule_path.exists():
                try:
                    import yara
                    rules = yara.compile(filepath=str(rule_path))
                    count = 0
                    for _ in rules:
                        count += 1
                    total_rules += count
                except Exception:
                    all_loaded = False
            else:
                all_loaded = False

        self.dashboard_tab.update_yara_status(all_loaded and total_rules > 0, total_rules)
