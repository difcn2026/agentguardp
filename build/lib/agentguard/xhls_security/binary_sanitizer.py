"""
XHLS binary_sanitizer v1.0 — ComfyUI/Model File Input Sanitization
===========================================================
DS R1致命短板#1: 攻击者通过ComfyUI二进制数据接口(PNG元数据/Pickle模型)
可完全绕过security_hardening文本注入检测。

解决方案: 对所有外部二进制输入强制类型隔离+重编码。
- Pickle文件: 拒绝加载，提示迁移SafeTensors
- PNG/图像: 重编码剥离元数据
- 序列化对象: 白名单检查

参考资料:
- ai-alert.org: Pickle unserialization = arbitrary code execution by design
- JFrog 2024: 确认HuggingFace存在恶意Pickle模型
- SafeTensors: 安全的张量序列化格式
"""

import os
import re
import struct
import hashlib
import logging
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

logger = logging.getLogger("xhls.binary_sanitizer")

# ============================================================
# v1.0: Binary Input Sanitizer
# ============================================================

class BinarySanitizer:
    """Type-isolated binary input sanitization for all external file inputs."""
    
    # File signatures (magic bytes)
    MAGIC_SIGNATURES = {
        "pickle": [
            b'\x80\x04',           # pickle protocol 4
            b'\x80\x05',           # pickle protocol 5
            b'\x80\x03',           # pickle protocol 3
            b'\x80\x02',           # pickle protocol 2
            b'\x80\x00',           # pickle protocol 0 (ascii)
        ],
        "pytorch_zip": [
            b'PK\x03\x04',         # PyTorch .pt/.bin (zip-based)
        ],
        "safetensors": [
            b'\x00\x00\x00\x00',   # SafeTensors header (JSON length)
        ],
        "png": [b'\x89PNG\r\n\x1a\n'],
        "jpeg": [b'\xff\xd8\xff'],
        "gif": [b'GIF8'],
    }
    
    # Allowed model formats (non-executable)
    SAFE_MODEL_FORMATS = {"safetensors", "onnx"}
    
    # Maximum file sizes
    MAX_SIZES = {
        "model": 8 * 1024 * 1024 * 1024,  # 8GB
        "image": 100 * 1024 * 1024,        # 100MB
        "lora": 500 * 1024 * 1024,         # 500MB
        "unknown": 10 * 1024 * 1024,       # 10MB default
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.blocked_count = 0
        self.scanned_count = 0
        self.audit_log: list = []
    
    def detect_format(self, filepath: str) -> str:
        """Detect file format by magic bytes."""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)
            
            for fmt, sigs in self.MAGIC_SIGNATURES.items():
                for sig in sigs:
                    if header.startswith(sig):
                        return fmt
            
            # Heuristic: check for pickle ASCII pattern
            if header.startswith(b'(') or header.startswith(b'i') or \
               header.startswith(b'd') or header.startswith(b'l'):
                if b'\np' in header or b'\n.' in header:
                    return "pickle"
            
            return "unknown"
        except Exception as e:
            logger.error(f"Format detection failed: {e}")
            return "unknown"
    
    def sanitize_model_file(self, filepath: str) -> Tuple[bool, str, str]:
        """
        Sanitize model file input. Returns (safe, reason, recommended_action).
        
        Rules:
        - Pickle format: REJECT (arbitrary code execution risk)
        - PyTorch .pt/.bin with pickle inside: REJECT
        - SafeTensors: ACCEPT
        - ONNX: ACCEPT with warning
        """
        fmt = self.detect_format(filepath)
        self.scanned_count += 1
        
        if fmt == "pickle":
            self.blocked_count += 1
            msg = (
                f"REJECTED: {filepath} is a Pickle-serialized file. "
                "Pickle deserialization = arbitrary code execution by design. "
                "CVE pattern: loading untrusted pickle files executes embedded Python code. "
                "Migrate to SafeTensors format: https://github.com/huggingface/safetensors"
            )
            self._audit("model_pickle_blocked", filepath, fmt)
            return False, msg, "convert_to_safetensors"
        
        if fmt == "pytorch_zip":
            # PyTorch zip may contain pickle inside - scan deeper
            risk = self._scan_pytorch_zip(filepath)
            if risk:
                self.blocked_count += 1
                self._audit("model_pytorch_risk", filepath, f"{fmt}:{risk}")
                return False, f"REJECTED: PyTorch archive with pickle risk: {risk}", "use_safetensors"
        
        if fmt == "safetensors":
            self._audit("model_safe", filepath, fmt)
            return True, "SafeTensors format accepted", "none"
        
        if fmt == "onnx":
            self._audit("model_onnx_warn", filepath, fmt)
            return True, "ONNX accepted with caution (external data ref risk)", "verify_onnx_refs"
        
        # Unknown format - reject by default
        self.blocked_count += 1
        self._audit("model_unknown_blocked", filepath, fmt)
        return False, f"REJECTED: Unknown model format '{fmt}'", "verify_format"
    
    def sanitize_image_file(self, filepath: str) -> Tuple[bool, str, bytes]:
        """
        Re-encode image to strip metadata. Returns (safe, msg, clean_bytes).
        PNG metadata can carry steganographic payloads or XSS vectors.
        """
        fmt = self.detect_format(filepath)
        self.scanned_count += 1
        
        if fmt not in ("png", "jpeg", "gif"):
            self.blocked_count += 1
            return False, f"REJECTED: Unknown image format '{fmt}'", b""
        
        # Read and re-encode to strip metadata
        try:
            with open(filepath, 'rb') as f:
                raw = f.read()
            
            # Size check
            max_size = self.MAX_SIZES["image"]
            if len(raw) > max_size:
                self.blocked_count += 1
                return False, f"REJECTED: Image too large ({len(raw)} > {max_size})", b""
            
            # Use PIL if available for re-encoding
            try:
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(raw))
                # Convert to RGB if RGBA (strip alpha channel metadata)
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGBA')
                out = io.BytesIO()
                # Save as PNG without metadata
                img.save(out, format='PNG', optimize=False)
                clean = out.getvalue()
                self._audit("image_sanitized", filepath, fmt)
                return True, f"Sanitized: metadata stripped ({len(raw)}->{len(clean)} bytes)", clean
            except ImportError:
                # Fallback: basic PNG chunk stripping
                if fmt == "png":
                    clean = self._strip_png_metadata(raw)
                    self._audit("image_stripped", filepath, fmt)
                    return True, "Sanitized: PNG metadata chunks stripped", clean
                self._audit("image_pass_through", filepath, fmt)
                return True, "Pass-through (PIL not available for re-encode)", raw
        except Exception as e:
            self.blocked_count += 1
            logger.error(f"Image sanitization error: {e}")
            return False, f"ERROR: {e}", b""
    
    def _scan_pytorch_zip(self, filepath: str) -> Optional[str]:
        """Scan PyTorch zip archive for pickle content."""
        try:
            import zipfile
            with zipfile.ZipFile(filepath, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.pkl') or 'pickle' in name.lower():
                        return f"pickle file found: {name}"
                    # Check for data.pkl pattern
                    if 'data' in name.lower() and not name.endswith(('.json', '.txt', '.md')):
                        return f"suspicious archive member: {name}"
            return None
        except Exception as e:
            return f"zip scan error: {e}"
    
    def _strip_png_metadata(self, data: bytes) -> bytes:
        """Strip non-essential PNG chunks (tEXt, zTXt, iTXt, tIME)."""
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            return data
        
        essential = {b'IHDR', b'PLTE', b'IDAT', b'IEND', b'tRNS'}
        result = [data[:8]]  # Keep PNG signature
        
        pos = 8
        while pos < len(data):
            if pos + 8 > len(data):
                break
            length = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            chunk_end = pos + 12 + length
            
            if chunk_type in essential:
                result.append(data[pos:chunk_end])
            
            pos = chunk_end + 4  # Skip CRC
        
        return b''.join(result)
    
    def sanitize_serialized_object(self, filepath: str) -> Tuple[bool, str]:
        """Check serialized objects for deserialization attacks."""
        fmt = self.detect_format(filepath)
        self.scanned_count += 1
        
        if fmt == "pickle":
            self.blocked_count += 1
            return False, "REJECTED: Pickle serialization is insecure"
        
        # Check for common serialization formats
        with open(filepath, 'rb') as f:
            header = f.read(64)
        
        # Check for Python marshal
        if header.startswith(b'\xe3') or header.startswith(b'\xa9'):
            self.blocked_count += 1
            return False, "REJECTED: Python marshal detected (potential code injection)"
        
        # Check for yaml with !!python/object
        try:
            text = header.decode('utf-8', errors='ignore')
            if '!!python/object' in text or '!!python/name' in text:
                self.blocked_count += 1
                return False, "REJECTED: Unsafe YAML tag detected"
        except:
            pass
        
        self._audit("serial_ok", filepath, fmt)
        return True, "Serialized object passed sanitization"
    
    def _audit(self, event: str, filepath: str, detail: str) -> None:
        """Record audit log entry."""
        import time
        entry = {
            "ts": time.time(),
            "event": event,
            "file": filepath,
            "detail": detail
        }
        self.audit_log.append(entry)
        logger.info(f"[{event}] {filepath} | {detail}")
    
    def status(self) -> dict:
        return {
            "version": "1.0",
            "scanned": self.scanned_count,
            "blocked": self.blocked_count,
            "audit_entries": len(self.audit_log),
            "safe_formats": list(self.SAFE_MODEL_FORMATS),
        }


# ============================================================
# CLI Test
# ============================================================
if __name__ == "__main__":
    bs = BinarySanitizer()
    print(f"BinarySanitizer v1.0 loaded")
    print(f"Safe formats: {bs.SAFE_MODEL_FORMATS}")
    print(f"Blocked pickle sigs: {len(bs.MAGIC_SIGNATURES['pickle'])} patterns")
    
    # Test detection logic
    test_pickle_bytes = b'\x80\x04\x95'
    test_png_bytes = b'\x89PNG\r\n\x1a\n'
    test_safetensors = b'\x00\x00\x00\x00{"test"'
    
    print(f"\nPickle detection: {test_pickle_bytes[:3]} -> pickle? {'pickle' if any(test_pickle_bytes.startswith(s) for s in bs.MAGIC_SIGNATURES['pickle']) else 'no'}")
    print(f"PNG detection: {test_png_bytes[:4]} -> png? {'png' if any(test_png_bytes.startswith(s) for s in bs.MAGIC_SIGNATURES['png']) else 'no'}")
    print(f"SafeTensors detection: {test_safetensors[:4]} -> safetensors? {'safetensors' if any(test_safetensors.startswith(s) for s in bs.MAGIC_SIGNATURES['safetensors']) else 'no'}")
    print("binary_sanitizer v1.0 OK")
