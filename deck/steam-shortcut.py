#!/usr/bin/env python3
"""Pure-Python (no deps) reader/editor for Steam's binary shortcuts.vdf.

Lets deck/steam-art.sh resolve the non-Steam shortcut's grid AppID and rename it
to pwnDeck without needing the `vdf` pip package on the Deck.

    steam-shortcut.py appid  <shortcuts.vdf> [name ...]              # print grid AppID
    steam-shortcut.py rename <shortcuts.vdf> <newname> [oldname ...] # rename + write

Matches a shortcut by AppName (case-insensitive); defaults to pwnDeck/protoPen.
Binary VDF uses only three type tags here: 0x00 nested map, 0x01 string,
0x02 uint32; maps end with 0x08.
"""

from __future__ import annotations

import struct
import sys

NAMES_DEFAULT = ("pwndeck", "protopen")


def _parse(data: bytes, i: int = 0):
    out: dict = {}
    while i < len(data):
        t = data[i]
        i += 1
        if t == 0x08:  # end of map
            return out, i
        j = data.index(b"\x00", i)
        key = data[i:j].decode("utf-8", "replace")
        i = j + 1
        if t == 0x00:
            val, i = _parse(data, i)
        elif t == 0x01:
            j = data.index(b"\x00", i)
            val = data[i:j].decode("utf-8", "replace")
            i = j + 1
        elif t == 0x02:
            val = struct.unpack("<I", data[i : i + 4])[0]
            i += 4
        else:
            raise ValueError(f"unsupported vdf type 0x{t:02x} at offset {i - 1}")
        out[key] = val
    return out, i


def _ser(d: dict) -> bytes:
    out = bytearray()
    for k, v in d.items():
        kb = k.encode("utf-8")
        if isinstance(v, dict):
            out += b"\x00" + kb + b"\x00" + _ser(v)
        elif isinstance(v, int):  # bool is an int subclass — fine
            out += b"\x02" + kb + b"\x00" + struct.pack("<I", int(v) & 0xFFFFFFFF)
        else:
            out += b"\x01" + kb + b"\x00" + str(v).encode("utf-8") + b"\x00"
    return bytes(out) + b"\x08"


def _entries(root: dict) -> dict:
    return root.get("shortcuts") or root.get("Shortcuts") or {}


def _match(entries: dict, names):
    wanted = tuple(n.lower() for n in names) or NAMES_DEFAULT
    for _key, e in entries.items():
        if isinstance(e, dict):
            nm = e.get("AppName") or e.get("appname") or ""
            if nm.lower() in wanted:
                return e
    return None


def main(argv) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd, path = argv[1], argv[2]
    data = open(path, "rb").read()
    root, _ = _parse(data)
    entries = _entries(root)

    if cmd == "list":
        for key, e in entries.items():
            if isinstance(e, dict):
                print(f"{key}\t{e.get('appid')}\t{e.get('AppName') or e.get('appname')}")
        return 0

    if cmd == "appid":
        e = _match(entries, argv[3:])
        if not e or e.get("appid") is None:
            return 1
        print(e["appid"] & 0xFFFFFFFF)
        return 0

    if cmd == "rename":
        if len(argv) < 4:
            print(__doc__)
            return 2
        newname = argv[3]
        e = _match(entries, argv[4:])
        if not e:
            return 1
        if (e.get("AppName") or e.get("appname")) == newname:
            return 0  # already named that — nothing to do
        e["AppName" if "AppName" in e or "appname" not in e else "appname"] = newname
        open(path + ".bak", "wb").write(data)  # backup before writing
        open(path, "wb").write(_ser(root))
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
