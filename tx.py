import argparse
import json
import os
from datetime import datetime

LEDGER_FILE = "ledger.json"

def load_ledger():
    if os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, "r") as f:
            return json.load(f)
    return {"transactions": [], "balances": {}}

def save_ledger(ledger):
    with open(LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=4)

def init_ledger():
    ledger = {"transactions": [], "balances": {}}
    save_ledger(ledger)
    print("✅ Ledger initialized")

def add_transaction(sender, receiver, amount):
    ledger = load_ledger()
    tx = {
        "from": sender,
        "to": receiver,
        "amount": amount,
        "timestamp": str(datetime.utcnow())
    }
    ledger["transactions"].append(tx)
    # Update balances
    ledger["balances"][sender] = ledger["balances"].get(sender, 100) - amount
    ledger["balances"][receiver] = ledger["balances"].get(receiver, 100) + amount
    save_ledger(ledger)
    print(f"✅ Transaction added: {sender} -> {receiver} : {amount}")

def list_transactions():
    ledger = load_ledger()
    for i, tx in enumerate(ledger["transactions"], 1):
        print(f"{i}. {tx['from']} -> {tx['to']} : {tx['amount']} at {tx['timestamp']}")

def show_balances():
    ledger = load_ledger()
    print("📊 Account Balances:")
    for account, balance in ledger["balances"].items():
        print(f"- {account}: {balance}")

def main():
    parser = argparse.ArgumentParser(description="Simple Transaction Simulator")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Initialize the ledger")
    subparsers.add_parser("list", help="List all transactions")
    subparsers.add_parser("show", help="Show account balances")

    add_parser = subparsers.add_parser("add", help="Add a transaction")
    add_parser.add_argument("from_account")
    add_parser.add_argument("to_account")
    add_parser.add_argument("amount", type=float)

    send_parser = subparsers.add_parser("send", help="Send tokens between accounts")
    send_parser.add_argument("--from", dest="from_account", required=True)
    send_parser.add_argument("--to", dest="to_account", required=True)
    send_parser.add_argument("--amount", type=float, required=True)

    args = parser.parse_args()

    if args.command == "init":
        init_ledger()
    elif args.command == "add":
        add_transaction(args.from_account, args.to_account, args.amount)
    elif args.command == "list":
        list_transactions()
    elif args.command == "show":
        show_balances()
    elif args.command == "send":
        add_transaction(args.from_account, args.to_account, args.amount)
    else:
        print("Unknown command")

if __name__ == "__main__":
    main()
