# -*- coding: utf-8 -*-
"""
XHLS Security Hardening v1.0 — RBAC + 审计日志 + 沙箱逃逸检测
===============================================================
  DS自评: 安全5/10 — 致命短板
  Token Security RSAC 2026: Machine-first identity for Agentic AI

新增:
  L1: RBAC权限模型 — 角色→允许工具→资源限制
  L2: 审计日志 — 全量操作记录+异常检测
  L3: 沙箱逃逸检测 — 危险模式匹配+资源监控

存储: A:\XDLS\security\
"""
import json, time, re, hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional
from enum import Enum

CST = timezone(timedelta(hours=8))
SEC_ROOT = Path(r"A:\XDLS\security")


class Role(Enum):
    ADMIN = "admin"        # 老板 — 全部权限
    ENGINEER = "engineer"  # 小黑 — 工程工具
    STRATEGIST = "strategist"  # 军师 — 只读+调度
    CREATOR = "creator"    # 小丫 — 内容工具
    GUEST = "guest"        # 外部 — 只读


# ═══════════════════════════════════════════════════════════
# L1: RBAC 权限模型
# ═══════════════════════════════════════════════════════════

class RBAC:
    """基于角色的访问控制"""

    ROLE_PERMISSIONS = {
        Role.ADMIN: {
            "tools": ["*"],  # 全部工具
            "paths": ["*"],
            "max_shell_timeout": 300,
            "can_modify_constitution": True,
            "can_deploy": True,
        },
        Role.ENGINEER: {
            "tools": ["shell", "python", "file_read", "file_write", "search", "memory_read", "memory_write"],
            "paths": ["A:\\XDLS\\", "C:\\Users\\Administrator\\Documents\\Codex\\"],
            "max_shell_timeout": 60,
            "can_modify_constitution": False,
            "can_deploy": True,
        },
        Role.STRATEGIST: {
            "tools": ["file_read", "search", "memory_read", "memory_write", "dispatch"],
            "paths": ["A:\\XDLS\\"],
            "max_shell_timeout": 0,  # 不能执行shell
            "can_modify_constitution": False,
            "can_deploy": False,
        },
        Role.CREATOR: {
            "tools": ["file_read", "file_write", "search", "memory_read", "comfyui", "ffmpeg"],
            "paths": ["A:\\XDLS\\outputs\\", "A:\\Projects\\"],
            "max_shell_timeout": 0,
            "can_modify_constitution": False,
            "can_deploy": False,
        },
        Role.GUEST: {
            "tools": ["file_read", "search", "memory_read"],
            "paths": ["A:\\XDLS\\reports\\"],
            "max_shell_timeout": 0,
            "can_modify_constitution": False,
            "can_deploy": False,
        },
    }

    DANGEROUS_COMMANDS = [
        r"Remove-Item\s+.+-Force", r"del\s+/[fq]", r"rm\s+-rf",
        r"format\s", r"diskpart", r"reg\s+(add|delete)",
        r"Stop-Process\s+-Force\s+-\w+\s+(Codex|codex|svchost|winlogon|lsass|csrss)",
        r"Set-ItemProperty\s+.+HKLM", r"netsh\s+firewall",
    ]

    def __init__(self):
        self.current_role = Role.ADMIN  # 默认管理员
        self.role_history: list[dict] = []

    def check_tool_access(self, tool: str, role: Role = None) -> tuple[bool, str]:
        role = role or self.current_role
        perms = self.ROLE_PERMISSIONS.get(role, {})
        allowed_tools = perms.get("tools", [])
        if "*" in allowed_tools or tool in allowed_tools:
            return True, ""
        return False, f"角色 {role.value} 无权使用工具: {tool}"

    def check_path_access(self, path: str, role: Role = None) -> tuple[bool, str]:
        role = role or self.current_role
        perms = self.ROLE_PERMISSIONS.get(role, {})
        allowed_paths = perms.get("paths", [])
        if "*" in allowed_paths:
            return True, ""
        for ap in allowed_paths:
            if path.lower().startswith(ap.lower()):
                return True, ""
        return False, f"角色 {role.value} 无权访问路径: {path}"

    def check_dangerous_command(self, command: str) -> tuple[bool, str]:
        for pattern in self.DANGEROUS_COMMANDS:
            if re.search(pattern, command, re.IGNORECASE):
                return True, f"匹配危险模式: {pattern}"
        return False, ""

    def escalate(self, target_role: Role, reason: str) -> bool:
        """权限提升 — 需记录理由"""
        self.role_history.append({
            "from": self.current_role.value,
            "to": target_role.value,
            "reason": reason,
            "timestamp": datetime.now(CST).isoformat(),
        })
        self.current_role = target_role
        return True

    def deescalate(self):
        """降权到ENGINEER"""
        return self.escalate(Role.ENGINEER, "auto_deescalate")


# ═══════════════════════════════════════════════════════════
# L2: 审计日志
# ═══════════════════════════════════════════════════════════

class AuditLogger:
    """全量操作审计 + 异常检测"""

    def __init__(self):
        self.log_file = SEC_ROOT / "audit.jsonl"
        self.anomaly_file = SEC_ROOT / "anomalies.jsonl"
        self.stats: dict[str, int] = {"total": 0, "blocked": 0, "anomalies": 0}
        self._load_stats()

    def _load_stats(self):
        sf = SEC_ROOT / "audit_stats.json"
        if sf.exists():
            try:
                self.stats.update(json.loads(sf.read_text(encoding="utf-8")))
            except:
                pass

    def _save_stats(self):
        SEC_ROOT.mkdir(parents=True, exist_ok=True)
        (SEC_ROOT / "audit_stats.json").write_text(json.dumps(self.stats), encoding="utf-8")

    def log(self, action: str, tool: str, role: str, result: str,
            detail: dict = None, ip: str = ""):
        entry = {
            "ts": datetime.now(CST).isoformat(),
            "action": action, "tool": tool, "role": role,
            "result": result, "detail": detail or {}, "ip": ip,
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self.stats["total"] += 1
        if result == "blocked":
            self.stats["blocked"] += 1

        # 异常检测: 短时间内大量失败
        self._detect_anomaly(entry)
        self._save_stats()

    def _detect_anomaly(self, entry: dict):
        # 简单规则: 连续5次blocked → 异常
        if self.stats["blocked"] > 0 and self.stats["blocked"] % 5 == 0:
            anomaly = {
                "ts": datetime.now(CST).isoformat(),
                "type": "excessive_blocks",
                "count": self.stats["blocked"],
                "last_action": entry["action"],
            }
            with open(self.anomaly_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(anomaly, ensure_ascii=False) + "\n")
            self.stats["anomalies"] += 1

    def recent(self, limit: int = 20) -> list[dict]:
        if not self.log_file.exists():
            return []
        lines = self.log_file.read_text(encoding="utf-8").strip().split("\n")
        return [json.loads(l) for l in lines[-limit:] if l.strip()]

    def stats_summary(self) -> dict:
        return {
            **self.stats,
            "recent_blocked": [e for e in self.recent(50) if e.get("result") == "blocked"][-5:],
        }


# ═══════════════════════════════════════════════════════════
# L3: 沙箱逃逸检测
# ═══════════════════════════════════════════════════════════

class SandboxEscapeDetector:
    """检测潜在的沙箱逃逸尝试"""

    ESCAPE_PATTERNS = [
        (r"os\.system\s*\(.+\)", "python_os_system"),
        (r"subprocess\.(call|run|Popen)\s*\(.+\)", "python_subprocess"),
        (r"eval\s*\(.+\)", "python_eval"),
        (r"exec\s*\(.+\)", "python_exec"),
        (r"__import__\s*\(.+\)", "python_import_hijack"),
        (r"ctypes\.", "python_ctypes"),
        (r"socket\.", "network_access"),
        (r"requests\.(get|post)", "network_request"),
        (r"Start-Process\s+.+-WindowStyle\s+Hidden", "hidden_process"),
        (r"Invoke-WebRequest\s+.+-OutFile", "download_file"),
        (r"New-Object\s+System\.Net\.", "dotnet_network"),
    ]

    RESOURCE_LIMITS = {
        "max_cpu_percent": 80,
        "max_memory_mb": 4096,
        "max_disk_write_mb": 1024,
        "max_network_mb": 100,
    }

    def __init__(self):
        self.violations: list[dict] = []
        self.resource_usage: dict[str, float] = {}

    def scan_command(self, command: str) -> list[dict]:
        """扫描命令中的逃逸模式"""
        findings = []
        for pattern, risk_type in self.ESCAPE_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                findings.append({"pattern": pattern, "type": risk_type, "severity": "high"})
        if findings:
            self.violations.append({
                "ts": datetime.now(CST).isoformat(),
                "command": command[:200],
                "findings": findings,
            })
        return findings

    def check_resource(self, cpu: float, mem_mb: float) -> list[str]:
        alerts = []
        if cpu > self.RESOURCE_LIMITS["max_cpu_percent"]:
            alerts.append(f"CPU超标: {cpu}% > {self.RESOURCE_LIMITS['max_cpu_percent']}%")
        if mem_mb > self.RESOURCE_LIMITS["max_memory_mb"]:
            alerts.append(f"内存超标: {mem_mb}MB > {self.RESOURCE_LIMITS['max_memory_mb']}MB")
        return alerts

    def stats(self) -> dict:
        return {
            "total_violations": len(self.violations),
            "recent_violations": self.violations[-5:],
            "resource_limits": self.RESOURCE_LIMITS,
        }


# ═══════════════════════════════════════════════════════════
# Security Hardening — 集成三层
# ═══════════════════════════════════════════════════════════

class SecurityHardening:
    """XHLS Security v1.0 — RBAC + Audit + Sandbox"""

    def __init__(self):
        self.rbac = RBAC()
        self.audit = AuditLogger()
        self.sandbox = SandboxEscapeDetector()

    def pre_exec_check(self, tool: str, params: dict, role: str = "admin") -> dict:
        """执行前三层检查"""
        role_enum = Role(role) if role in [r.value for r in Role] else Role.ENGINEER

        # L1: RBAC检查
        allowed, reason = self.rbac.check_tool_access(tool, role_enum)
        if not allowed:
            self.audit.log("pre_check", tool, role, "blocked", {"reason": reason})
            return {"ok": False, "layer": "rbac", "reason": reason}

        # L2: 危险命令检查 (仅shell工具)
        if tool in ("shell", "run_shell") and "command" in params:
            dangerous, pattern = self.rbac.check_dangerous_command(params["command"])
            if dangerous:
                self.audit.log("pre_check", tool, role, "blocked",
                               {"reason": f"dangerous_pattern:{pattern}", "cmd": params["command"][:100]})
                return {"ok": False, "layer": "dangerous_cmd", "reason": f"匹配危险模式: {pattern}"}

        # L3: 沙箱逃逸检测
        if tool in ("shell", "python", "run_python"):
            cmd = params.get("command", params.get("code", ""))
            findings = self.sandbox.scan_command(cmd)
            if findings:
                self.audit.log("pre_check", tool, role, "warning",
                               {"findings": findings, "cmd": cmd[:100]})
                return {"ok": True, "layer": "sandbox_warning", "warnings": findings}

        self.audit.log("pre_check", tool, role, "passed", {})
        return {"ok": True, "layer": "all_clear"}

    def post_exec_audit(self, tool: str, role: str, success: bool, detail: dict = None):
        self.audit.log("post_exec", tool, role, "success" if success else "failed", detail or {})

    def stats(self) -> dict:
        return {
            "rbac": {"current_role": self.rbac.current_role.value},
            "audit": self.audit.stats_summary(),
            "sandbox": self.sandbox.stats(),
        }


# ═══════════════════════════════════════════════════════════
# Test
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=== Security Hardening v1.0 Test ===\n")
    sec = SecurityHardening()

    # 1. RBAC test
    print("1. RBAC权限检查...")
    r1 = sec.pre_exec_check("shell", {"command": "Get-ChildItem"}, "engineer")
    print(f"   工程师执行ls: {r1}")
    r2 = sec.pre_exec_check("shell", {"command": "Remove-Item -Force C:\\"}, "engineer")
    print(f"   工程师危险命令: {r2}")
    r3 = sec.pre_exec_check("shell", {"command": "Get-ChildItem"}, "guest")
    print(f"   访客执行shell: {r3}")

    # 2. Sandbox escape test
    print("\n2. 沙箱逃逸检测...")
    r4 = sec.pre_exec_check("python", {"code": "os.system('whoami')"}, "engineer")
    print(f"   os.system: {r4}")
    r5 = sec.pre_exec_check("python", {"code": "print(1+1)"}, "engineer")
    print(f"   正常代码: {r5}")

    # 3. Audit log
    print("\n3. 审计日志...")
    sec.post_exec_audit("search", "engineer", True, {"query": "test"})
    sec.post_exec_audit("shell", "admin", False, {"error": "timeout"})
    print(f"   总计: {sec.audit.stats['total']}, blocked: {sec.audit.stats['blocked']}")

    # 4. Full stats
    print("\n4. 安全统计...")
    print(json.dumps(sec.stats(), ensure_ascii=False, indent=2, default=str))

    print("\n=== Security Hardening v1.0 Complete ===")
