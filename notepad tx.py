#!/usr/bin/env python3
"""
Transaction Simulator (works with your wallet.py keys)

Commands:
  init        -> create ledger.json if missing
  send        -> sign & append a transaction to ledger
  balance     -> compute balance for a wallet/address
  history     -> list transactions (all or filtered)

Assumptions:
- Wallet files are in the SAME folder: <name>_public.pem, <name>_private.pem
- Address = SHA-256(public_key_pem_bytes)
"""

import argparse
import base64
import getpass
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

LEDGER_PATH = Path("ledger.json")

# ---------- Helpers ----------

def read_ledger() -> List[Dict[str, Any]]:
    if not LEDGER_PATH.exists():
        return []
    try:
        return json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []

def write_ledger(rows: List[Dict[str, Any]]) -> None:
    LEDGER_PATH.write_text(json.dumps(rows, indent=2), encoding="utf-8")

def pubkey_path(name: str) -> Path:
    return Path(f"{name}_public.pem")

def privkey_path(name: str) -> Path:
    return Path(f"{name}_private.pem")

def load_public_pem(name: str) -> bytes:
    p = pubkey_path(name)
    if not p.exists():
        raise FileNotFoundError(f"Missing public key: {p.name}")
    return p.read_bytes()

def load_private_key(name: str, password: Optional[str]):
    p = privkey_path(name)
    if not p.exists():
        raise FileNotFoundError(f"Missing private key: {p.name}")
    data = p.read_bytes()
    # Try unencrypted; if fails, load with passphrase
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:
        if password is None:
            pw = getpass.getpass("Enter passphrase for private key: ")
            password_bytes = pw.encode("utf-8")
        else:
            password_bytes = password.encode("utf-8")
        return serialization.load_pem_private_key(data, password=password_bytes)

def addr_from_pub_pem(pub_pem: bytes) -> str:
    return hashlib.sha256(pub_pem).hexdigest()

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256_hex(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

# ---------- Transaction primitives ----------

def tx_digest_bytes(tx_core: Dict[str, Any]) -> bytes:
    core = {
        "from": tx_core["from"],
        "to": tx_core["to"],
        "amount": tx_core["amount"],
        "timestamp": tx_core["timestamp"],
        "nonce": tx_core["nonce"],
    }
    return json.dumps(core, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sign_tx(private_key, tx_core: Dict[str, Any]) -> str:
    payload = tx_digest_bytes(tx_core)
    signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("utf-8")

def verify_tx(pub_key, tx_core: Dict[str, Any], signature_b64: str) -> bool:
    try:
        payload = tx_digest_bytes(tx_core)
        signature = base64.b64decode(signature_b64.encode("utf-8"))
        pub_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def load_public_key_obj(pub_pem: bytes):
    return serialization.load_pem_public_key(pub_pem)

# ---------- Commands ----------

def cmd_init(_args):
    if LEDGER_PATH.exists():
        print(f"Ledger already exists: {LEDGER_PATH}")
        return
    write_ledger([])
    print(f"Created empty ledger: {LEDGER_PATH}")

def resolve_name_or_address(name_or_addr: str) -> str:
    s = name_or_addr.strip().lower()
    if len(s) == 64 and all(c in "0123456789abcdef" for c in s):
        return s  # already an address
    pub_pem = load_public_pem(name_or_addr)
    return addr_from_pub_pem(pub_pem)

def cmd_send(args):
    sender = args.sender
    recipient = args.recipient
    amount = float(args.amount)
    password = args.password

    pub_pem = load_public_pem(sender)
    address_from = addr_from_pub_pem(pub_pem)
    address_to = resolve_name_or_address(recipient)

    private_key = load_private_key(sender, password=password)
    public_key_obj = load_public_key_obj(pub_pem)

    ledger = read_ledger()
    nonce = sum(1 for t in ledger if t.get("from") == address_from)
    tx_core = {
        "from": address_from,
        "to": address_to,
        "amount": amount,
        "timestamp": now_iso(),
        "nonce": nonce,
    }

    signature_b64 = sign_tx(private_key, tx_core)
    tx_full = {
        "id": sha256_hex(json.dumps(tx_core, sort_keys=True).encode("utf-8")),
        **tx_core,
        "signature": signature_b64,
        "sender_public_key_pem": pub_pem.decode("utf-8"),
    }

    if not verify_tx(public_key_obj, tx_core, signature_b64):
        print("❌ Signature verification failed; transaction not recorded.")
        return

    ledger.append(tx_full)
    write_ledger(ledger)
    print("✅ Transaction recorded.")
    print(json.dumps(tx_full, indent=2))

def cmd_balance(args):
    target = args.name_or_address
    address = resolve_name_or_address(target)
    ledger = read_ledger()
    bal = 0.0
    for tx in ledger:
        if tx.get("to") == address:   bal += float(tx.get("amount", 0))
        if tx.get("from") == address: bal -= float(tx.get("amount", 0))
    print(f"Balance for {address}: {bal}")

def cmd_history(args):
    ledger = read_ledger()
    if not ledger:
        print("No transactions yet.")
        return
    filt = args.name_or_address
    if filt:
        address = resolve_name_or_address(filt)
        rows = [tx for tx in ledger if tx.get("from") == address or tx.get("to") == address]
    else:
        rows = ledger
    print(json.dumps(rows, indent=2))

# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(description="Simple Transaction Simulator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="Create ledger.json if missing")

    p_send = sub.add_parser("send", help="Send amount from --from NAME to --to NAME/ADDRESS")
    p_send.add_argument("--from", dest="sender", required=True)
    p_send.add_argument("--to", dest="recipient", required=True)
    p_send.add_argument("--amount", required=True)
    p_send.add_argument("--password", default=None)

    p_bal = sub.add_parser("balance", help="Show balance for NAME or ADDRESS")
    p_bal.add_argument("--who", dest="name_or_address", required=True)

    p_hist = sub.add_parser("history", help="Show transactions (all or filtered)")
    p_hist.add_argument("--filter", dest="name_or_address", default=None)

    args = parser.parse_args()
    if args.cmd == "init":      cmd_init(args)
    elif args.cmd == "send":    cmd_send(args)
    elif args.cmd == "balance": cmd_balance(args)
    elif args.cmd == "history": cmd_history(args)

if __name__ == "__main__":
    main()
