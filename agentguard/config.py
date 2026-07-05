"""AgentGuard Config — API Key management."""
import json
import os
from pathlib import Path

CONFIG_PATH = Path.home() / ".agentguard" / "config.json"


def get_api_key() -> str:
    """Get user configured GLM API key. Returns empty string if not set."""
    if not CONFIG_PATH.exists():
        return ""
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        return data.get("glm_api_key", "")
    except Exception:
        return ""


def set_api_key(key: str) -> bool:
    """Save GLM API key to config file."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        if CONFIG_PATH.exists():
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        else:
            data = {}
        data["glm_api_key"] = key
        CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def get_api_url() -> str:
    """Get GLM API URL."""
    if not CONFIG_PATH.exists():
        return "https://open.bigmodel.cn/api/paas/v4/chat/completions"
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        return data.get("glm_api_url", "https://open.bigmodel.cn/api/paas/v4/chat/completions")
    except Exception:
        return "https://open.bigmodel.cn/api/paas/v4/chat/completions"


def get_model() -> str:
    """Get model name."""
    return "glm-5.2"
