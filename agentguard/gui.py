"""
AgentGuard Pro — 极客桌面
=========================
原生桌面应用。暗色终端美学。不依赖浏览器。
线程安全加固版。
"""
import sys, os, threading, json
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from pathlib import Path
from datetime import datetime

if sys.platform == "win32":
    for s in ("stdout", "stderr"):
        try:
            x = getattr(sys, s)
            if x and hasattr(x, "reconfigure"):
                x.reconfigure(encoding="utf-8", errors="replace")
        except: pass

# ══════════ 配色 ══════════
C = {
    "bg":       "#0a0a0a",
    "panel":    "#0f0f0f",
    "border":   "#1f1f1f",
    "text":     "#b0b0b0",
    "dim":      "#555555",
    "accent":   "#00ff88",
    "red":      "#ff4444",
    "orange":   "#ff8c00",
    "yellow":   "#ffd700",
    "blue":     "#4488ff",
    "input_bg": "#111111",
    "input_fg": "#d0d0d0",
    "sel_bg":   "#1a2a1a",
}
FONT  = ("Cascadia Code", 10)
FONT_SM = ("Cascadia Code", 9)
FONT_BIG = ("Cascadia Code", 13)
FONT_HUGE = ("Cascadia Code", 24)


class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AgentGuard Pro")
        self.root.geometry("900x640")
        self.root.minsize(720, 480)
        self.root.configure(bg=C["bg"])
        self._last_result = None
        self._scanning = False
        self._scan_lock = threading.Lock()
        self._worker = None
        self._closing = False
        self._max_lines = 2000
        self._mode = "dry-run"
        self._proxy_on = False
        self._tier = self._check_license()
        self._build()
        self._bind_keys()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._print("AGENTGUARD PRO v0.3.0", "green")
        self._print("ctrl+o browse  |  ctrl+enter scan  |  ctrl+shift+enter pipeline  |  esc cancel  |  ctrl+s export", "dim")
        self._print("", "")
        self.root.after(2000, self._check_update)

    # ═══ UI ═══════════════════════════════
    def _check_license(self):
        """Check license/trial status. Returns 'pro', 'trial', or 'free'."""
        from pathlib import Path as _P
        from datetime import datetime as _dt, timedelta as _td
        import json as _json

        LICENSE_FILE = _P.home() / ".agentguard" / "license.key"
        TRIAL_FILE = _P.home() / ".agentguard" / "trial.json"
        TRIAL_DAYS = 7

        if LICENSE_FILE.exists():
            try:
                from agentguard.license_verify import verify_license
                key = LICENSE_FILE.read_text().strip()
                status = verify_license(key)
                if status.valid and status.tier == "pro":
                    return "pro"
            except Exception:
                pass

        now = _dt.utcnow()
        if TRIAL_FILE.exists():
            try:
                trial = _json.loads(TRIAL_FILE.read_text())
                started = _dt.fromisoformat(trial["started"])
                deadline = started + _td(days=TRIAL_DAYS)
                if now < deadline:
                    days = (deadline - now).days + 1
                    tk.messagebox.showinfo("Trial Active", f"Pro trial: {days} day(s) remaining.")
                    return "trial"
                else:
                    go_buy = tk.messagebox.askyesno(
                        "Trial Expired",
                        "Your 7-day Pro trial has expired.\n\n"
                        "Buy Pro to unlock: DS Review | Auto-fix | Full pipeline\n\n"
                        "Open purchase page?"
                    )
                    if go_buy:
                        import webbrowser
                        webbrowser.open("http://47.236.24.76:1088")
                    return "free"
            except Exception:
                pass

        start_trial = tk.messagebox.askyesno(
            "AgentGuard Pro Trial",
            f"Welcome! You have a {TRIAL_DAYS}-day free Pro trial.\n\n"
            "Pro features: DS Review | Auto-fix | Full pipeline\n\n"
            "Start trial?"
        )
        if start_trial:
            TRIAL_FILE.parent.mkdir(parents=True, exist_ok=True)
            TRIAL_FILE.write_text(_json.dumps({"started": now.isoformat()}))
            tk.messagebox.showinfo("Trial Started", f"Pro trial active for {TRIAL_DAYS} days.")
            return "trial"
        return "free"


    # Version check
    def _check_update(self):
        """Check GitHub for newer release (non-blocking)."""
        import urllib.request, json as _json_j
        VERSION = "v0.5.0"
        def _fetch():
            try:
                req = urllib.request.Request(
                    "https://api.github.com/repos/difcn2026/agentguard/releases/latest",
                    headers={"User-Agent": "AgentGuard-Pro/0.3.0"})
                resp = urllib.request.urlopen(req, timeout=8)
                data = _json_j.loads(resp.read())
                latest = data.get("tag_name", "")
                if latest and latest > VERSION:
                    go = tk.messagebox.askyesno(
                        "Update Available",
                        f"AgentGuard {latest} is available.\n\n"
                        f"You are running {VERSION}.\n\n"
                        "Open download page?"
                    )
                    if go:
                        __import__("os").startfile("https://agentguardp.com")
            except Exception:
                pass  # Silently fail - update check is optional
        threading.Thread(target=_fetch, daemon=True).start()

    def _build(self):
        r = self.root

        # ── Top bar ──
        top = tk.Frame(r, bg=C["panel"], height=36, highlightthickness=0)
        top.pack(fill=tk.X, side=tk.TOP)
        top.pack_propagate(False)

        self._lbl(top, "AgentGuard Pro", C["accent"], FONT_BIG).pack(side=tk.LEFT, padx=14)

        self._buy_btn = tk.Label(top, text=" BUY PRO ", fg="#0a0a0a", bg="#f97316",
            font=("Cascadia Code", 9, "bold"), cursor="hand2", padx=8, pady=2)
        self._buy_btn.bind("<Button-1>", lambda e: __import__("os").startfile("http://47.236.24.76:1088"))
        if self._tier != "pro":
            self._buy_btn.pack(side=tk.RIGHT, padx=14)

        # help button
        self._help_btn = tk.Label(top, text=" ? ", fg=C["dim"], bg=C["panel"],
            font=("Cascadia Code", 9, "bold"), cursor="hand2", padx=8, pady=2)
        self._help_btn.bind("<Button-1>", self._show_help_menu)
        self._help_btn.pack(side=tk.RIGHT, padx=2)

        # mode buttons
        self._mode_btns = {}
        for m, label in [("dry-run","dry-run"), ("safe","safe"), ("fix","fix")]:
            b = tk.Label(top, text=label, fg=C["dim"], bg=C["panel"],
                         font=FONT_SM, padx=10, cursor="hand2")
            b.pack(side=tk.LEFT)
            b.bind("<Button-1>", lambda e, m=m: self._set_mode(m))
            self._mode_btns[m] = b
        self._mode_btns["dry-run"].configure(fg=C["accent"])

        # toggles
        self._bandit_var = tk.BooleanVar(value=False)
        self._ds_var = tk.BooleanVar(value=False)
        for var, label in [(self._bandit_var,"bandit"), (self._ds_var,"ds")]:
            cb = tk.Checkbutton(top, text=label, variable=var,
                                bg=C["panel"], fg=C["dim"], selectcolor=C["panel"],
                                font=FONT_SM, activebackground=C["panel"],
                                activeforeground=C["text"])
            cb.pack(side=tk.LEFT, padx=(4,0))

        # proxy indicator
        pf = tk.Frame(top, bg=C["panel"])
        pf.pack(side=tk.RIGHT, padx=10)
        self._proxy_dot = tk.Label(pf, text="○", fg=C["dim"], bg=C["panel"], font=("",8), cursor="hand2")
        self._proxy_dot.pack(side=tk.LEFT)
        self._proxy_lbl = tk.Label(pf, text="proxy", fg=C["dim"], bg=C["panel"], font=FONT_SM, cursor="hand2")
        self._proxy_lbl.pack(side=tk.LEFT, padx=(2,0))
        for w in (self._proxy_dot, self._proxy_lbl):
            w.bind("<Button-1>", lambda e: self._toggle_proxy())

        # ── Path bar ──
        pb = tk.Frame(r, bg=C["bg"])
        pb.pack(fill=tk.X, padx=12, pady=(10,0))
        tk.Label(pb, text="target", fg=C["dim"], bg=C["bg"], font=FONT_SM).pack(side=tk.LEFT, padx=(0,6))
        self._path_var = tk.StringVar(value=os.getcwd())
        self._path_entry = tk.Entry(pb, textvariable=self._path_var,
                                    bg=C["input_bg"], fg=C["input_fg"],
                                    insertbackground=C["accent"], relief=tk.FLAT,
                                    font=FONT, bd=0, highlightthickness=0)
        self._path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)

        # ── Action buttons ──
        ab = tk.Frame(r, bg=C["bg"])
        ab.pack(fill=tk.X, padx=12, pady=(6,0))
        self._scan_btn = self._btn(ab, "scan", C["accent"], self._do_scan)
        self._scan_btn.pack(side=tk.LEFT, padx=(0,6))
        self._pipe_btn = self._btn(ab, "pipeline", C["blue"], self._do_pipeline)
        self._pipe_btn.pack(side=tk.LEFT, padx=(0,6))
        self._btn(ab, "browse", C["dim"], self._browse).pack(side=tk.LEFT)

        self._btn(ab, "export", C["dim"], self._export).pack(side=tk.RIGHT, padx=(4,0))
        self._btn(ab, "config", C["dim"], self._config_dialog).pack(side=tk.RIGHT, padx=(4,0))

        # ── Output ──
        of = tk.Frame(r, bg=C["bg"])
        of.pack(fill=tk.BOTH, expand=True, padx=12, pady=(8,4))
        self._output = tk.Text(of, bg=C["panel"], fg=C["text"],
                               insertbackground=C["accent"], relief=tk.FLAT,
                               font=FONT, wrap=tk.WORD, bd=0,
                               padx=12, pady=10, state=tk.DISABLED)
        self._output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = tk.Scrollbar(of, bg=C["border"], troughcolor=C["bg"],
                          activebackground=C["dim"])
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._output.configure(yscrollcommand=sb.set)
        sb.configure(command=self._output.yview)
        self._output.tag_configure("green", foreground=C["accent"])
        self._output.tag_configure("red", foreground=C["red"])
        self._output.tag_configure("orange", foreground=C["orange"])
        self._output.tag_configure("yellow", foreground=C["yellow"])
        self._output.tag_configure("dim", foreground=C["dim"])
        self._output.tag_configure("bold", font=(FONT[0], FONT[1], "bold"))
        self._output.tag_configure("title", font=FONT_HUGE, foreground=C["accent"])

        # ── Status bar ──
        sf = tk.Frame(r, bg=C["panel"], height=24)
        sf.pack(fill=tk.X, side=tk.BOTTOM)
        sf.pack_propagate(False)
        self._status = tk.Label(sf, text="ready", fg=C["dim"], bg=C["panel"],
                                font=FONT_SM, anchor=tk.W)
        self._status.pack(side=tk.LEFT, padx=12, fill=tk.X, expand=True)
        self._progress_lbl = tk.Label(sf, text="", fg=C["accent"], bg=C["panel"], font=FONT_SM)
        self._progress_lbl.pack(side=tk.RIGHT, padx=12)

    def _lbl(self, parent, text, color, font):
        return tk.Label(parent, text=text, fg=color,
                       bg=C["panel"] if parent == self.root else parent.cget("bg"), font=font)

    def _btn(self, parent, text, color, cmd):
        b = tk.Label(parent, text=text, fg=color, bg=C["bg"],
                     font=FONT_SM, padx=12, pady=4, cursor="hand2")
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e, c=color, w=b: w.configure(fg="#fff", bg=C["sel_bg"]))
        b.bind("<Leave>", lambda e, c=color, w=b: w.configure(fg=c, bg=C["bg"]))
        return b

    # ═══ Keys ═══════════════════════════════
    def _bind_keys(self):
        r = self.root
        r.bind("<Control-o>", lambda e: self._browse())
        r.bind("<Control-Return>", lambda e: self._do_scan())
        r.bind("<Control-Shift-Return>", lambda e: self._do_pipeline())
        r.bind("<Escape>", lambda e: self._cancel_scan())
        r.bind("<Control-s>", lambda e: self._export())
        r.bind("<Control-comma>", lambda e: self._config_dialog())

    # ═══ Window close ═══════════════════════
    def _on_close(self):
        self._closing = True
        with self._scan_lock:
            self._scanning = False
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=2)
        self.root.destroy()

    # ═══ Mode ═══════════════════════════════
    def _set_mode(self, m):
        self._mode = m
        for k, b in self._mode_btns.items():
            b.configure(fg=C["accent"] if k == m else C["dim"])

    # ═══ Proxy toggle ═══════════════════════
    def _toggle_proxy(self):
        self._proxy_on = not self._proxy_on
        self._proxy_dot.configure(
            text="●" if self._proxy_on else "○",
            fg=C["accent"] if self._proxy_on else C["dim"])
        self._proxy_lbl.configure(fg=C["accent"] if self._proxy_on else C["dim"])
        self._print(f"proxy {'ON' if self._proxy_on else 'OFF'}", "green" if self._proxy_on else "dim")

    # Help popup menu
    def _show_help_menu(self, event=None):
        menu = tk.Menu(self.root, tearoff=0, bg=C["panel"], fg=C["text"],
            activebackground=C["border"], activeforeground="#fff",
            font=FONT_SM, bd=0)
        menu.add_command(label="Documentation",
            command=lambda: __import__("os").startfile(
                "https://github.com/difcn2026/agentguard#readme"))
        menu.add_command(label="Report Issue",
            command=lambda: __import__("os").startfile(
                "https://github.com/difcn2026/agentguard/issues"))
        menu.add_separator()
        menu.add_command(label="About AgentGuard Pro v0.3.0",
            command=lambda: tk.messagebox.showinfo("About",
                "AgentGuard Pro v0.3.0\nAI Code Security Scanner\n\n"
                "by XHLS Team\nhttps://github.com/difcn2026/agentguard"))
        menu.post(event.x_root + self.root.winfo_rootx(),
            event.y_root + self.root.winfo_rooty())

    # ═══ Browse ═════════════════════════════
    def _browse(self):
        d = filedialog.askopenfilename(title="select target file", filetypes=[("Python","*.py"),("All","*.*")])
        if not d:
            d = filedialog.askdirectory(title="or select target folder")
        if d:
            self._path_var.set(d)
            self._print(f"target: {d}", "dim")

    # ═══ Scan ═══════════════════════════════
    def _do_scan(self):
        with self._scan_lock:
            if self._scanning:
                self._print("scan already in progress", "dim")
                return
            self._scanning = True
        path = self._path_var.get().strip()
        if not path:
            with self._scan_lock: self._scanning = False
            self._print("error: no target folder", "red")
            return
        bandit = self._bandit_var.get()
        ds = self._ds_var.get()
        mode = self._mode
        self._set_scanning_ui(True)
        self._worker = threading.Thread(
            target=self._scan, args=(path, False, bandit, ds, mode), daemon=True)
        self._worker.start()

    def _do_pipeline(self):
        with self._scan_lock:
            if self._scanning:
                self._print("scan already in progress", "dim")
                return
            self._scanning = True
        path = self._path_var.get().strip()
        if not path:
            with self._scan_lock: self._scanning = False
            self._print("error: no target folder", "red")
            return
        bandit = self._bandit_var.get()
        ds = self._ds_var.get()
        mode = self._mode
        self._set_scanning_ui(True)
        self._worker = threading.Thread(
            target=self._scan, args=(path, True, bandit, ds, mode), daemon=True)
        self._worker.start()

    def _set_scanning_ui(self, v):
        if v:
            self._scan_btn.configure(fg=C["dim"])
            self._pipe_btn.configure(fg=C["dim"])
            self._status.configure(text="scanning...", fg=C["accent"])
        else:
            self._scan_btn.configure(fg=C["accent"])
            self._pipe_btn.configure(fg=C["blue"])
            self._status.configure(text="ready", fg=C["dim"])
            self._progress_lbl.configure(text="")

    def _cancel_scan(self):
        with self._scan_lock:
            was_scanning = self._scanning
            self._scanning = False
        if was_scanning:
            self._print("cancel requested...", "yellow")
            self._set_scanning_ui(False)
            self._update_status("cancelling...")

    def _still_scanning(self):
        with self._scan_lock:
            return self._scanning

    # ═══ Scan worker ════════════════════════
    def _scan(self, path, is_pipeline, use_bandit, use_ds, mode):
        try:
            if is_pipeline:
                if not self._still_scanning(): return
                self._print(f"\nPIPELINE  scan -> review -> fix  [{mode}]", "green")
                self._update_status("phase 1/3: scanning...")
                from agentguard.pipeline import pipeline as run_pipe
                if not self._still_scanning(): return
                result = run_pipe(path=path, mode=mode, use_ds=use_ds,
                                  write=mode=="fix", use_bandit=use_bandit)
                if not self._still_scanning(): return
                scan = result.get("scan", {})
                fix = result.get("fix", {})
                self._show_stats(scan.get("critical",0), scan.get("high",0),
                                 scan.get("medium",0), scan.get("low",0))
                if fix.get("fixed_count", 0):
                    self._print(f"fixed: {fix['fixed_count']}  manual: {fix.get('manual_count',0)}  files: {fix.get('files_changed',0)}", "green")
                if fix.get("diff"):
                    self._print("--- diff ---", "dim")
                    for line in fix["diff"].split("\n")[:50]:
                        self._print(f"  {line}", "dim")
            else:
                if not self._still_scanning(): return
                self._print(f"\nSCAN  {path}", "green")
                self._update_status("scanning...")

                if use_bandit:
                    from agentguard.scanner.bandit_adapter import scan_with_bandit
                    findings = scan_with_bandit(path)
                else:
                    from agentguard.scanner.code_scanner import CodeScanner
                    scanner = CodeScanner(tier="pro")
                    result = scanner.scan_directory(path)
                    findings = [{
                        "rule_id": f.rule_id, "severity": str(f.severity),
                        "line": f.line, "message": f.message,
                        "code_snippet": f.code_snippet or "",
                    } for f in result.findings]

                if not self._still_scanning(): return

                crit = sum(1 for f in findings if f.get("severity")=="CRITICAL")
                high = sum(1 for f in findings if f.get("severity")=="HIGH")
                med  = sum(1 for f in findings if f.get("severity")=="MEDIUM")
                low  = sum(1 for f in findings if f.get("severity")=="LOW")

                self._show_stats(crit, high, med, low)
                self._print_findings(findings)

                self._last_result = {
                    "critical":crit,"high":high,"medium":med,"low":low,
                    "total":len(findings),"findings":findings,
                    "path":path,"bandit":use_bandit,"ds":use_ds,
                    "time":datetime.now().strftime("%Y-%m-%d %H:%M")
                }

            if self._still_scanning():
                self._update_status("done")
                self._print("--- done ---\n", "dim")
            else:
                self._print("--- cancelled ---\n", "yellow")
        except Exception as e:
            self._print(f"error: {e}", "red")
            self._update_status("error")
        finally:
            self.root.after(0, self._scan_done)

    def _scan_done(self):
        with self._scan_lock:
            self._scanning = False
            self._worker = None
        self._set_scanning_ui(False)

    def _show_stats(self, crit, high, med, low):
        total = crit + high + med + low
        if total == 0:
            self._print("  no issues found", "green")
            return
        self._print(f"  crit:{crit}  high:{high}  med:{med}  low:{low}  total:{total}", "bold")

    def _print_findings(self, findings):
        if not findings: return
        for f in findings[:200]:
            sev = f.get("severity","?")
            color = {"CRITICAL":"red","HIGH":"orange","MEDIUM":"yellow","LOW":"dim"}.get(sev,"")
            self._print(f"  [{f.get('rule_id','?')}] L{f.get('line','?')}: {f.get('message','')}", color)
            if f.get("code_snippet"):
                self._print(f"      {f['code_snippet'].strip()}", "dim")
        if len(findings) > 200:
            self._print(f"  ... and {len(findings)-200} more", "dim")

    # ═══ Export ═════════════════════════════
    def _export(self):
        if not self._last_result or not self._last_result.get("findings"):
            self._print("nothing to export - run a scan first", "dim")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON","*.json"),("Markdown","*.md"),("All files","*.*")])
        if not fp: return
        d = self._last_result
        try:
            if fp.endswith(".md"):
                md = f"# AgentGuard Scan Report\n\n**path:** {d['path']}\n**time:** {d['time']}\n\n"
                md += f"|severity|count|\n|---|---|\n"
                md += f"|critical|{d['critical']}|\n|high|{d['high']}|\n|medium|{d['medium']}|\n|low|{d['low']}|\n\n"
                for f in d["findings"][:500]:
                    md += f"- **{f.get('severity','?')}** [{f.get('rule_id','?')}] L{f.get('line','?')}: {f.get('message','')}\n"
                    if f.get("code_snippet"):
                        md += f"  ```\n{f['code_snippet'].strip()}\n  ```\n"
                Path(fp).write_text(md, encoding="utf-8")
            else:
                Path(fp).write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
            self._print(f"exported -> {fp}", "green")
        except Exception as e:
            self._print(f"export failed: {e}", "red")

    # ═══ Config ═════════════════════════════
    CONFIG_FILE = Path.home() / ".agentguard" / "config.json"
    def _load_config(self):
        """Load saved config or return defaults."""
        try:
            self.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            if self.CONFIG_FILE.exists():
                return json.loads(self.CONFIG_FILE.read_text())
        except Exception:
            pass
        return {"llm_api_url": "", "llm_api_key": "", "proxy": "",
                "license_server": "http://47.236.24.76:8989",
                "website": "https://agentguardp.com"}
    def _save_config(self, data):
        """Save config to disk."""
        try:
            self.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            self.CONFIG_FILE.write_text(json.dumps(data, indent=2))
        except Exception:
            pass
    # ═══ Config Dialog ══════════════════════
    def _config_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("config")
        dlg.geometry("440x300")
        dlg.configure(bg=C["panel"])
        dlg.resizable(False, False)
        dlg.transient(self.root)

        def make_row(label, default, row):
            tk.Label(dlg, text=label, fg=C["dim"], bg=C["panel"], font=FONT_SM)\
              .grid(row=row, column=0, sticky=tk.W, padx=14, pady=(10,2))
            var = tk.StringVar(value=default)
            e = tk.Entry(dlg, textvariable=var, bg=C["input_bg"], fg=C["input_fg"],
                         insertbackground=C["accent"], relief=tk.FLAT, font=FONT)
            e.grid(row=row+1, column=0, sticky=tk.EW, padx=14)
            return var

        cfg = self._load_config()
        ds_url = make_row("LLM API URL", cfg.get("llm_api_url", ""), 0)
        ds_key = make_row("LLM API Key", cfg.get("llm_api_key", ""), 2)
        proxy_var = make_row("proxy", cfg.get("proxy", ""), 4)
        dlg.grid_columnconfigure(0, weight=1)

        def save():
            self._print("config saved", "dim")
            new_cfg = {
                "llm_api_url": ds_url.get(),
                "llm_api_key": ds_key.get(),
                "proxy": proxy_var.get(),
                "license_server": cfg.get("license_server", "http://47.236.24.76:8989"),
                "website": cfg.get("website", "https://agentguardp.com"),
            }
            self._save_config(new_cfg)
            dlg.destroy()

        self._btn(dlg, "save", C["accent"], save).grid(row=6, column=0, pady=14, padx=14, sticky=tk.E)

    # ═══ Output helpers ═════════════════════
    def _print(self, text, tag=""):
        def _do():
            if self._closing: return
            self._output.configure(state=tk.NORMAL)
            try:
                lc = int(self._output.index("end-1c").split(".")[0])
                if lc > self._max_lines:
                    self._output.delete("1.0", f"{lc - self._max_lines}.0")
            except: pass
            self._output.insert(tk.END, text + "\n", tag)
            self._output.configure(state=tk.DISABLED)
            self._output.see(tk.END)
        self.root.after(0, _do)

    def _update_status(self, text):
        self.root.after(0, lambda: self._progress_lbl.configure(text=text))

    def run(self):
        self.root.mainloop()


def main():
    App().run()


if __name__ == "__main__":
    main()
