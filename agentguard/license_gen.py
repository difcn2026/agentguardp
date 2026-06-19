"""
AgentGuard License Generator v0.1
==================================
Generates cryptographically signed license keys.
Only the seller (you) runs this. Never ship the private key.

Usage:
    python license_gen.py --email buyer@example.com --tier pro --expiry 2027-06-18
"""

import json
import uuid
import hashlib
import base64
import argparse
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


# ============================================================
# CONFIG: Change these for your deployment
# ============================================================
PRODUCT_NAME = "AgentGuard"
PRIVATE_KEY_PATH = Path(__file__).parent / "license_private.pem"
PUBLIC_KEY_PATH = Path(__file__).parent / "license_public.pem"
KEY_SIZE = 2048


@dataclass
class LicensePayload:
    """Data embedded in a license key."""
    product: str
    license_id: str
    email: str
    tier: str  # "free" | "pro" | "enterprise"
    issued_at: str
    expiry: str  # ISO date, or "perpetual"
    machine_hash: str = ""  # Bound to machine if set

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> "LicensePayload":
        d = json.loads(data)
        return cls(**d)


class LicenseGenerator:
    """
    Generates signed license keys.

    Architecture:
        License = base64( payload_json + "." + rsa_signature )

    Verification (client-side):
        1. Decode base64
        2. Split on last "."
        3. Verify RSA signature against embedded public key
        4. Check expiry
        5. Check machine binding (if any)
    """

    def __init__(self):
        self._ensure_keys()

    def _ensure_keys(self):
        """Generate RSA keypair if not exists."""
        if not PRIVATE_KEY_PATH.exists():
            print(f"[*] Generating RSA {KEY_SIZE}-bit keypair...")
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=KEY_SIZE,
            )
            public_key = private_key.public_key()

            PRIVATE_KEY_PATH.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            PUBLIC_KEY_PATH.write_bytes(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            print(f"[+] Keys saved: {PRIVATE_KEY_PATH.name}, {PUBLIC_KEY_PATH.name}")
            print("[!] Guard license_private.pem — never commit it!")

    def generate(
        self,
        email: str,
        tier: str = "pro",
        expiry_days: int = 365,
        machine_hash: str = "",
    ) -> str:
        """
        Generate a license key.

        Args:
            email: Buyer's email
            tier: "free", "pro", or "enterprise"
            expiry_days: Days until expiry (0 = perpetual)
            machine_hash: Optional machine binding

        Returns:
            License key string (base64)
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        now = datetime.utcnow()
        if expiry_days > 0:
            expiry = (now + timedelta(days=expiry_days)).strftime("%Y-%m-%d")
        else:
            expiry = "perpetual"

        payload = LicensePayload(
            product=PRODUCT_NAME,
            license_id=str(uuid.uuid4())[:8].upper(),
            email=email,
            tier=tier,
            issued_at=now.strftime("%Y-%m-%d"),
            expiry=expiry,
            machine_hash=machine_hash,
        )

        payload_json = payload.to_json()

        # Sign with RSA
        private_key = load_pem_private_key(
            PRIVATE_KEY_PATH.read_bytes(), password=None
        )
        signature = private_key.sign(
            payload_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Encode: payload + "." + signature (both base64url)
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return f"{PRODUCT_NAME}-{payload_b64}.{sig_b64}"


def main():
    parser = argparse.ArgumentParser(description="AgentGuard License Generator")
    parser.add_argument("--email", required=True, help="Licensee email")
    parser.add_argument("--tier", default="pro", choices=["free", "pro", "enterprise"])
    parser.add_argument("--expiry-days", type=int, default=365, help="Days until expiry (0=perpetual)")
    parser.add_argument("--machine", default="", help="Machine hash to bind (optional)")
    args = parser.parse_args()

    gen = LicenseGenerator()
    key = gen.generate(
        email=args.email,
        tier=args.tier,
        expiry_days=args.expiry_days,
        machine_hash=args.machine,
    )
    print(f"\nLicense Key:\n{key}\n")
    print(f"Email : {args.email}")
    print(f"Tier  : {args.tier}")
    print(f"Expiry: {'perpetual' if args.expiry_days == 0 else f'{args.expiry_days} days'}")


if __name__ == "__main__":
    main()
