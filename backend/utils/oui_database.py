"""
Simple OUI lookup helper (loads OUI map from data file if available)
"""

import json
from pathlib import Path

DATA_FILE = Path(__file__).parent.parent / "data" / "cctv_signatures.json"


def load_oui_map():
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


OUI_MAP = load_oui_map()


def lookup(mac: str):
    if not mac:
        return None
    mac = mac.upper().replace("-", ":")
    oui = ":".join(mac.split(":")[:3])
    return OUI_MAP.get(oui)
