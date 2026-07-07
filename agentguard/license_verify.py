"""
AgentGuard License Verifier v0.1
=================================
Client-side license validation. No network calls needed.

Usage:
    from agentguard.license_verify import verify_license
    result = verify_license("AgentGuard-xxxx.yyyy")
"""

import json
import base64
import hashlib
import platform
import sys
import uuid as _uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple


def _get_base_dir():
    if getattr(sys, 'frozen', False):
        return Path(sys._MEIPASS)
    return Path(__file__).parent


PUBLIC_KEY_PATH = _get_base_dir() / "license_public.pem"
LICENSE_STORE = Path.home() / ".agentguard" / "license.key"
TRIAL_STORE = Path.home() / ".agentguard" / "trial.json"
TRIAL_DAYS = 14  # 14-day Pro trial: user brings own API key


@dataclass
class LicenseStatus:
    valid: bool
    tier: str
    email: str
    license_id: str
    expiry: str
    reason: str = ""
    days_left: int = -1


def get_machine_hash() -> str:
    factors = [platform.node(), platform.machine(), platform.processor()]
    raw = "|".join(factors)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def verify_license(key: str, machine_hash: str = "") -> LicenseStatus:
    if not key.startswith("AgentGuard-"):
        return LicenseStatus(False, "free", "", "", "", "Invalid key format", 0)
    encoded = key[len("AgentGuard-"):]
    if "." not in encoded:
        return LicenseStatus(False, "free", "", "", "", "Missing signature", 0)
    last_dot = encoded.rfind(".")
    payload_b64 = encoded[:last_dot]
    sig_b64 = encoded[last_dot + 1:]
    try:
        payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode()
        payload = json.loads(payload_json)
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
    except Exception as e:
        return LicenseStatus(False, "free", "", "", "", f"Decode error: {e}", 0)
    if not PUBLIC_KEY_PATH.exists():
        return LicenseStatus(False, "free", "", "", "",
                           "Public key missing - reinstall AgentGuard", 0)
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        public_key = load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
        public_key.verify(sig_bytes, payload_json.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                       salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
    except Exception:
        return LicenseStatus(False, "free", "", "", "",
                           "Signature verification failed - key is forged", 0)
    if payload.get("machine_hash"):
        actual_hash = machine_hash or get_machine_hash()
        if payload["machine_hash"] != actual_hash:
            return LicenseStatus(False, "free", "", "", "",
                               "Machine mismatch", 0)
    expiry_str = payload.get("expiry", "perpetual")
    days_left = -1
    if expiry_str != "perpetual":
        try:
            expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d")
            if datetime.utcnow() > expiry_date:
                return LicenseStatus(False, payload["tier"], payload["email"],
                                   payload["license_id"], expiry_str, "License expired", 0)
            days_left = (expiry_date - datetime.utcnow()).days
        except ValueError:
            pass
    return LicenseStatus(True, payload.get("tier", "free"),
                        payload.get("email", ""), payload.get("license_id", ""),
                        expiry_str, "OK", days_left)


def activate(key: str) -> bool:
    status = verify_license(key)
    if not status.valid:
        print(f"Activation failed: {status.reason}")
        return False
    LICENSE_STORE.parent.mkdir(parents=True, exist_ok=True)
    LICENSE_STORE.write_text(key)
    print(f"Activated! Tier: {status.tier} | {status.days_left} days remaining")
    return True


def _get_install_date() -> str:
    """Get or set the first-install date for trial tracking."""
    if TRIAL_STORE.exists():
        try:
            data = json.loads(TRIAL_STORE.read_text())
            return data.get("install_date", "")
        except Exception:
            pass
    TRIAL_STORE.parent.mkdir(parents=True, exist_ok=True)
    install_date = datetime.utcnow().strftime("%Y-%m-%d")
    TRIAL_STORE.write_text(json.dumps({"install_date": install_date}))
    return install_date


def get_trial_info() -> dict:
    """Return trial status: {active, days_left, install_date}."""
    install_date_str = _get_install_date()
    try:
        install_date = datetime.strptime(install_date_str, "%Y-%m-%d")
        elapsed = (datetime.utcnow() - install_date).days
        days_left = max(0, TRIAL_DAYS - elapsed)
        return {
            "active": days_left > 0,
            "days_left": days_left,
            "install_date": install_date_str,
            "trial_days": TRIAL_DAYS,
        }
    except ValueError:
        return {"active": False, "days_left": 0, "install_date": install_date_str, "trial_days": TRIAL_DAYS}


def get_active_tier() -> str:
    """Return active tier: pro if licensed, pro if in trial, else free."""
    if LICENSE_STORE.exists():
        key = LICENSE_STORE.read_text().strip()
        if key:
            status = verify_license(key)
            if status.valid:
                return status.tier
    trial = get_trial_info()
    if trial["active"]:
        return "pro"
    return "free"


def deactivate() -> bool:
    removed = False
    if LICENSE_STORE.exists():
        LICENSE_STORE.unlink()
        removed = True
    if TRIAL_STORE.exists():
        TRIAL_STORE.unlink()
        removed = True
    return removed
