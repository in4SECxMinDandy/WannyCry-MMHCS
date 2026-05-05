import logging

import customtkinter as ctk


class TextboxHandler(logging.Handler):
    """Logging handler that appends log messages to a CTkTextbox."""
    def __init__(self, textbox: ctk.CTkTextbox):
        super().__init__()
        self.textbox = textbox

    def emit(self, record: logging.LogRecord):
        msg = self.format(record)
        def append():
            self.textbox.configure(state="normal")
            self.textbox.insert("end", msg + "\n")
            self.textbox.configure(state="disabled")
            self.textbox.yview("end")
        # Ensure thread-safety by scheduling UI update in the main loop
        self.textbox.after(0, append)

class LogsTab(ctk.CTkFrame):
    """Tab hiển thị logs (nhật ký) của ứng dụng."""
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Tiêu đề
        self.title_label = ctk.CTkLabel(
            self, text="Nhật Ký Hệ Thống (Logs)", font=ctk.CTkFont(size=18, weight="bold")
        )
        self.title_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

        # Textbox hiển thị log
        self.textbox = ctk.CTkTextbox(self, wrap="word", font=ctk.CTkFont(family="Consolas", size=12))
        self.textbox.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.textbox.configure(state="disabled")

        # Cấu hình logging handler
        handler = TextboxHandler(self.textbox)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)

        # Ghi log khởi tạo
        logging.getLogger("GUI").info("Logs tab initialized.")
