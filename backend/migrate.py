#!/usr/bin/env python3
from db import Database, migrate


def main():
    db = Database()
    migrate(db)
    print(f"Migrations applied for engine={db.engine}")


if __name__ == "__main__":
    main()
