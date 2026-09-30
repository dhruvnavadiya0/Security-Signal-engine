from __future__ import annotations

import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "bank_lab.sqlite3"
STATEMENTS_DIR = DATA_DIR / "statements"

USERS = [
    (1, "Aarav Mehta", "aarav.mehta@example.test", "Aarav123!", "customer", "111-22-3333"),
    (2, "Naina Shah", "naina.shah@example.test", "Naina123!", "customer", "222-33-4444"),
    (3, "Kabir Rao", "kabir.rao@example.test", "Kabir123!", "customer", "333-44-5555"),
    (4, "Meera Iyer", "meera.iyer@example.test", "Meera123!", "customer", "444-55-6666"),
    (5, "Admin User", "admin@example.test", "Admin123!", "admin", "000-00-0000"),
]

ACCOUNTS = [
    (1, 1, "ACC-100001", "Savings", "Mumbai Main", 894320.45),
    (2, 1, "ACC-100002", "Demat", "Mumbai Main", 102345.10),
    (3, 2, "ACC-100101", "Savings", "Pune Central", 56420.88),
    (4, 3, "ACC-100201", "Salary", "Navi Mumbai", 231980.12),
    (5, 4, "ACC-100301", "Savings", "Thane West", 78210.77),
    (6, 5, "ACC-999999", "Operations", "HQ", 15000000.00),
]

TICKETS = [
    (1, 1, "Card declined at merchant", "Please check the card terminal issue for my savings account."),
    (2, 2, "Failed UPI transfer", "My transfer failed but the amount was debited."),
    (3, 3, "Statement mismatch", "The exported statement totals do not match the dashboard."),
    (4, 4, "Profile update not saved", "My mobile number change did not persist."),
]

TRANSACTIONS = [
    (1, 1, "ACME Retail", -1820.50, "Card purchase - groceries"),
    (2, 1, "Salary Credit", 125000.00, "Monthly salary from Orion Systems"),
    (3, 2, "Brokerage Fee", -850.00, "Demat maintenance charge"),
    (4, 3, "Rent Payment", -22000.00, "Monthly rent transfer"),
    (5, 4, "Vendor Payout", 45000.00, "Invoice 8812 payment"),
    (6, 5, "System Sweep", 500000.00, "Internal liquidity movement"),
]


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATEMENTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def bootstrap() -> None:
    conn = connect()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            ssn TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            account_no TEXT NOT NULL,
            account_type TEXT NOT NULL,
            branch TEXT NOT NULL,
            balance REAL NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            account_id INTEGER NOT NULL,
            counterparty TEXT NOT NULL,
            amount REAL NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )

    if cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0:
        cur.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", USERS)
        cur.executemany("INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?)", ACCOUNTS)
        now = datetime.utcnow()
        populated_transactions = []
        for idx, tx in enumerate(TRANSACTIONS, start=1):
            populated_transactions.append(
                (
                    tx[0],
                    tx[1],
                    tx[2],
                    tx[3],
                    tx[4],
                    (now - timedelta(days=idx * 3)).isoformat(timespec="seconds") + "Z",
                )
            )
        cur.executemany("INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?)", populated_transactions)
        populated_tickets = []
        for idx, ticket in enumerate(TICKETS, start=1):
            populated_tickets.append(
                (
                    ticket[0],
                    ticket[1],
                    ticket[2],
                    ticket[3],
                    (now - timedelta(days=idx)).isoformat(timespec="seconds") + "Z",
                )
            )
        cur.executemany("INSERT INTO tickets VALUES (?, ?, ?, ?, ?)", populated_tickets)
        _write_statements()
        conn.commit()

    conn.close()


def _write_statements() -> None:
    STATEMENTS_DIR.mkdir(parents=True, exist_ok=True)
    for account in ACCOUNTS:
        statement = STATEMENTS_DIR / f"{account[2]}.txt"
        statement.write_text(
            "BANK LAB STATEMENT\n"
            f"Account: {account[2]}\n"
            f"Type: {account[3]}\n"
            f"Branch: {account[4]}\n"
            f"Opening balance: {account[5]:.2f}\n"
            "This is fake training data only.\n",
            encoding="utf-8",
        )


def fetch_one(query: str, params: tuple = ()):
    conn = connect()
    row = conn.execute(query, params).fetchone()
    conn.close()
    return row


def fetch_all(query: str, params: tuple = ()):
    conn = connect()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


def run(query: str, params: tuple = ()) -> None:
    conn = connect()
    conn.execute(query, params)
    conn.commit()
    conn.close()
