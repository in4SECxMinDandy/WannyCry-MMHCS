"""Tab Bảng Điều Khiển — tổng quan trạng thái và kết quả quét gần nhất (WannaCry & BlackCat)."""

import customtkinter as ctk


class DashboardTab(ctk.CTkFrame):
    """Bảng điều khiển hiển thị trạng thái engine và tóm tắt quét."""

    def __init__(self, master) -> None:
        super().__init__(master)
        self._build_ui()

    def _build_ui(self) -> None:
        """Xây dựng UI bảng điều khiển."""
        header = ctk.CTkLabel(
            self,
            text="Ransomware Detector Lite — Bảng Điều Khiển",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        header.pack(pady=(20, 10))

        desc = ctk.CTkLabel(
            self,
            text="Phát hiện WannaCry & BlackCat: ML Engine + PE Analyzer + YARA Rules",
            font=ctk.CTkFont(size=13),
            text_color="gray",
        )
        desc.pack(pady=(0, 20))

        status_frame = ctk.CTkFrame(self)
        status_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(
            status_frame,
            text="Trạng Thái Engine Phát Hiện",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).pack(pady=(10, 5))

        self.ml_status = ctk.CTkLabel(status_frame, text="ML Engine: Chưa Tải", text_color="orange")
        self.ml_status.pack(anchor="w", padx=20, pady=2)

        self.pe_status = ctk.CTkLabel(status_frame, text="PE Analyzer: Sẵn Sàng", text_color="green")
        self.pe_status.pack(anchor="w", padx=20, pady=2)

        self.yara_status = ctk.CTkLabel(status_frame, text="YARA Engine: Chưa Tải", text_color="orange")
        self.yara_status.pack(anchor="w", padx=20, pady=2)

        summary_frame = ctk.CTkFrame(self)
        summary_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(
            summary_frame,
            text="Tóm Tắt Lần Quét Gần Nhất",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).pack(pady=(10, 5))

        self.summary_text = ctk.CTkLabel(
            summary_frame,
            text="Chưa có lần quét nào.\n\nChạy quét từ tab Quét File để xem kết quả tại đây.",
            font=ctk.CTkFont(size=12),
            justify="left",
        )
        self.summary_text.pack(pady=(5, 15), padx=20, anchor="w")

        disc_frame = ctk.CTkFrame(self)
        disc_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(
            disc_frame,
            text="Tuyên Bố Miễn Trừ",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="red",
        ).pack(pady=(10, 5))
        ctk.CTkLabel(
            disc_frame,
            text=(
                "Công cụ này chỉ dành cho mục đích nghiên cứu học thuật.\n"
                "Chỉ quét hệ thống bạn sở hữu hoặc có quyền phân tích rõ ràng.\n"
                "Tác giả không chịu trách nhiệm về việc sử dụng sai mục đích."
            ),
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).pack(pady=(0, 10))

    def update_ml_status(self, loaded: bool) -> None:
        """Cập nhật trạng thái ML Engine.

        Args:
            loaded: True nếu model đã được tải.
        """
        if loaded:
            self.ml_status.configure(text="ML Engine: Đã Tải", text_color="green")
        else:
            self.ml_status.configure(text="ML Engine: Chưa Tải", text_color="orange")

    def update_yara_status(self, loaded: bool, rule_count: int = 0) -> None:
        """Cập nhật trạng thái YARA Engine.

        Args:
            loaded: True nếu rules đã được tải.
            rule_count: Số lượng rule đã biên dịch.
        """
        if loaded:
            self.yara_status.configure(
                text=f"YARA Engine: Đã Tải ({rule_count} rules)", text_color="green"
            )
        else:
            self.yara_status.configure(text="YARA Engine: Chưa Tải", text_color="orange")

    def update_summary(self, summary: dict) -> None:
        """Cập nhật tóm tắt lần quét gần nhất.

        Args:
            summary: Dict từ ReportGenerator.generate_summary.
        """
        text = (
            f"Tổng số file đã quét: {summary.get('total', 0)}\n"
            f"Phát hiện WannaCry: {summary.get('wannacry', 0)}\n"
            f"Phát hiện BlackCat: {summary.get('blackcat', 0)}\n"
            f"Nghi ngờ: {summary.get('suspicious', 0)}\n"
            f"An toàn: {summary.get('benign', 0)}\n"
            f"YARA matches: {summary.get('yara_hits', 0)}\n"
        )
        self.summary_text.configure(text=text)
