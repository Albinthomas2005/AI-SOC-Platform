#!/usr/bin/env python3
"""Add or update an explicit SOC username and role in the configured SQLite DB."""

import argparse
import re
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import database  # noqa: E402


VALID_ROLES = ("L1", "L2", "L3", "admin")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")


def add_soc_user(username, role):
    if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("username must be 1-128 letters, digits, dot, underscore, @, or hyphen")
    if role not in VALID_ROLES:
        raise ValueError("role must be one of: " + ", ".join(VALID_ROLES))

    updated_at = datetime.now(timezone.utc).isoformat()
    with closing(database.get_connection()) as connection, connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS soc_users (
                username TEXT PRIMARY KEY,
                role TEXT NOT NULL CHECK (role IN ('L1', 'L2', 'L3', 'admin')),
                updated_at TEXT NOT NULL
            )
        """)
        connection.execute(
            """INSERT INTO soc_users (username, role, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(username) DO UPDATE SET
                 role = excluded.role, updated_at = excluded.updated_at""",
            (username, role, updated_at),
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="explicit Dashboard-to-SOC username")
    parser.add_argument("role", choices=VALID_ROLES, help="role to assign; no role is assumed")
    args = parser.parse_args(argv)
    try:
        add_soc_user(args.username, args.role)
    except ValueError as error:
        parser.error(str(error))
    print(f"SOC user added or updated: {args.username} ({args.role})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
