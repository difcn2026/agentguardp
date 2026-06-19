"""
AgentGuard GUI — 一键扫描窗口
双击运行，选文件夹，点扫描，看结果。
"""
import sys
import os
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from pathlib import Path

# Fix Windows encoding
if sys.platform == "win32":
    for stream in ("stdout", "stderr"):
        try:
            s = getattr(sys, stream)
            if s is not None and hasattr(s, "reconfigure"):
                s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def run_scan():
    path = path_var.get().strip()
    if not path:
        messagebox.showwarning("提示", "请先选择要扫描的文件夹")
        return

    scan_btn.config(state="disabled", text="扫描中...")
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, f"正在扫描: {path}\n")
    result_text.insert(tk.END, "─" * 50 + "\n")
    root.update()

    try:
        from agentguard.scanner.code_scanner import CodeScanner
        from agentguard.reporter.reporter import terminal_report

        scanner = CodeScanner(tier="free")
        result = scanner.scan_directory(path)

        report = terminal_report(result, verbose=False)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, report)

        if result.passed:
            status_var.set("通过 — 未发现高危问题")
        else:
            status_var.set(f"发现 {result.critical_count + result.high_count} 个高危问题")
    except Exception as e:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"扫描出错: {e}")
        status_var.set("扫描失败")
    finally:
        scan_btn.config(state="normal", text="开始扫描")


def browse_folder():
    folder = filedialog.askdirectory(title="选择要扫描的文件夹")
    if folder:
        path_var.set(folder)


def main():
    """Entry point for console_scripts."""
    global root, path_var, scan_btn, result_text, status_var

    root = tk.Tk()
    root.title("AgentGuard — AI 代码安全扫描")
    root.geometry("780x580")
    root.minsize(600, 400)
    root.configure(bg="#1e1e2e")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TButton", font=("微软雅黑", 10), padding=6)
    style.configure("TLabel", font=("微软雅黑", 10), background="#1e1e2e", foreground="#cdd6f4")
    style.configure("TEntry", font=("Consolas", 10))

    header = tk.Label(root, text="AgentGuard", font=("微软雅黑", 18, "bold"),
                      fg="#ef4444", bg="#1e1e2e")
    header.pack(pady=(20, 4))

    sub = tk.Label(root, text="AI 代码安全扫描 — 选文件夹，点扫描", font=("微软雅黑", 10),
                   fg="#888", bg="#1e1e2e")
    sub.pack(pady=(0, 16))

    path_frame = tk.Frame(root, bg="#1e1e2e")
    path_frame.pack(fill="x", padx=24)

    path_var = tk.StringVar(value=os.getcwd())
    path_entry = tk.Entry(path_frame, textvariable=path_var,
                          font=("Consolas", 10), bg="#313244", fg="#cdd6f4",
                          insertbackground="#cdd6f4", relief="flat")
    path_entry.pack(side="left", fill="x", expand=True, ipady=4)

    browse_btn = ttk.Button(path_frame, text="浏览...", command=browse_folder)
    browse_btn.pack(side="left", padx=(8, 0))

    scan_btn = tk.Button(root, text="开始扫描", command=run_scan,
                         font=("微软雅黑", 12, "bold"), bg="#ef4444", fg="white",
                         activebackground="#dc2626", activeforeground="white",
                         relief="flat", padx=40, pady=8, cursor="hand2")
    scan_btn.pack(pady=16)

    status_var = tk.StringVar(value="就绪 — 选择文件夹后点击扫描")
    status_label = tk.Label(root, textvariable=status_var,
                            font=("微软雅黑", 9), fg="#a6adc8", bg="#1e1e2e")
    status_label.pack(pady=(0, 8))

    result_frame = tk.Frame(root, bg="#1e1e2e")
    result_frame.pack(fill="both", expand=True, padx=24, pady=(0, 16))

    result_text = tk.Text(result_frame, font=("Consolas", 10),
                          bg="#11111b", fg="#cdd6f4", insertbackground="#cdd6f4",
                          relief="flat", wrap="none")
    result_text.pack(side="left", fill="both", expand=True)

    scrollbar = ttk.Scrollbar(result_frame, command=result_text.yview)
    scrollbar.pack(side="right", fill="y")
    result_text.config(yscrollcommand=scrollbar.set)

    footer = tk.Label(root, text="AgentGuard v0.1  |  MIT  |  XHLS Team",
                      font=("微软雅黑", 8), fg="#585b70", bg="#1e1e2e")
    footer.pack(pady=(0, 8))

    root.mainloop()


if __name__ == "__main__":
    main()
