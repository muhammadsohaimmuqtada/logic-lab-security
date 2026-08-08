#!/usr/bin/env python3
from pathlib import Path
from app.config import Config
from app.db import reset_database

path = Path(Config.DATABASE_PATH)
reset_database(path)
print(f"Logic Lab database reset: {path}")
print("Seeded users: alice, bob, carol, dave, auditor, student")
print("Demo password: Password1!")
