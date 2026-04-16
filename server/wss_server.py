#!/usr/bin/env python3
"""
Neverlose WSS Server - Port 30030

Handles the WebSocket protocol used by the neverlose client.
Now supports full bidirectional communication:
  - Initial 3 frames: Auth JSON + module blob + key blob
  - Client message handling: CreateEntry, UpdateEntry, Init, ConfigAck
  - AES-128-CBC + LZ4 decrypt/encrypt for binary messages
  - FlatBuffer parsing and response generation
  - Filesystem operations: scripts, configs, languages

Usage:
  nix-shell -p "python3.withPackages (ps: [ps.websockets ps.pycryptodome ps.lz4])" openssl --run "python3 server/wss_server.py"
"""

import asyncio
import ssl
import json
import os
import sys
import logging
import time
import ipaddress
import struct
from pathlib import Path
from datetime import datetime

try:
    import websockets
except ImportError:
    print("Missing websockets. Run with:")
    print(
        '  nix-shell -p "python3.withPackages (ps: [ps.websockets ps.pycryptodome ps.lz4])" openssl --run "python3 server/wss_server.py"'
    )
    sys.exit(1)

from module_builder import (
    load_module,
    save_module,
    parse_module_data,
    build_module,
    wrap_module,
    compress_module,
    encrypt_module,
    decrypt_module,
    decompress_module,
    FBBuilder,
)

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("Missing pycryptodome. Install with: pip install pycryptodome")
    sys.exit(1)

try:
    import lz4.block
except ImportError:
    print("Missing lz4. Install with: pip install lz4")
    sys.exit(1)

# ============================================================================
# Constants
# ============================================================================

HOST = "0.0.0.0"
PORT = 30030

AUTH_MESSAGE = "fz8XfUGGBvylN7IW"
AUTH_DATA = "5aAxpFpna5QqvYMv"

# AES-128-CBC key and IV (matching the Rust server)
AES_KEY = bytes.fromhex("643831562A4B0F652559061470494A7D")
AES_IV = b"5aAxpFpna5QqvYMv"

DATA_DIR = Path(__file__).parent / "data"
CERT_FILE = Path(__file__).parent / "cert.pem"
KEY_FILE = Path(__file__).parent / "key.pem"

# Working directory: nl/ (located in CS:GO game directory)
# The cheat runs from: C:\Program Files (x86)\Steam\steamapps\common\csgo legacy\nl\
NL_DIR = Path(r"C:\Program Files (x86)\Steam\steamapps\common\csgo legacy\nl")
SCRIPTS_DIR = NL_DIR / "scripts"
CONFIGS_DIR = NL_DIR / "configs"
LANGS_DIR = NL_DIR / "langs"

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S"
)
log = logging.getLogger("wss")

# Load payloads at startup
ORIGINAL_MODULE = (DATA_DIR / "module.bin").read_bytes()
KEY_BLOB = (DATA_DIR / "key.bin").read_bytes()

# Parse the original module to get baseline data
_original_inner = decompress_module(decrypt_module(ORIGINAL_MODULE))
MODULE_DATA = parse_module_data(_original_inner)

# Add scripts from filesystem to MODULE_DATA
# (parse_module_data may not parse them correctly from original module)
if SCRIPTS_DIR.exists():
    existing_ids = {e["entry_id"] for e in MODULE_DATA.get("script_entries", [])}
    for scr_file in sorted(SCRIPTS_DIR.glob("*.lua")):
        try:
            parts = scr_file.stem.split("_", 1)
            entry_id = int(parts[0]) if parts[0].isdigit() else 0
            name = parts[1] if len(parts) > 1 else scr_file.stem
            if entry_id not in existing_ids:
                MODULE_DATA.setdefault("script_entries", []).append(
                    {
                        "entry_id": entry_id,
                        "timestamp": int(scr_file.stat().st_mtime),
                        "name": name,
                        "author": "user",
                    }
                )
                existing_ids.add(entry_id)
        except Exception as e:
            log.warning(f"Failed to add script {scr_file}: {e}")

assert len(ORIGINAL_MODULE) == 385360, (
    f"module.bin size mismatch: {len(ORIGINAL_MODULE)}"
)
assert len(KEY_BLOB) == 80, f"key.bin size mismatch: {len(KEY_BLOB)}"

# Message log for analysis
MSG_LOG = []

# In-memory storage for entries (entry_id counter per connection)
entry_counter = 0

# Module data storage (will be updated on CreateEntry/UpdateEntry)
current_module_inner = None
current_module_encrypted = None


def rebuild_module():
    """Rebuild the module with current MODULE_DATA + filesystem entries."""
    global current_module_inner, current_module_encrypted
    inner = build_module(MODULE_DATA, SCRIPTS_DIR, CONFIGS_DIR)
    wrapped = wrap_module(inner)
    compressed = compress_module(wrapped)
    encrypted = encrypt_module(compressed)
    current_module_inner = inner
    current_module_encrypted = encrypted
    log.info(f"  [Module] Rebuilt: {len(encrypted)} bytes")
    return encrypted


# Build initial module
rebuild_module()

# Use original module for now (rebuilt has FlatBuffer structure issues)
current_module_encrypted = ORIGINAL_MODULE


# ============================================================================
# Crypto helpers
# ============================================================================


def decrypt_message(data: bytes) -> bytes:
    """AES-128-CBC decrypt with PKCS#7 unpadding."""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = cipher.decrypt(data)
    return unpad(decrypted, AES.block_size)


def encrypt_message(data: bytes) -> bytes:
    """AES-128-CBC encrypt with PKCS#7 padding."""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(data, AES.block_size)
    return cipher.encrypt(padded)


def decompress_message(data: bytes) -> bytes:
    """LZ4 block decompress (4-byte LE uncompressed size header)."""
    if len(data) < 4:
        raise ValueError("Data too short for LZ4 header")
    uncompressed_size = struct.unpack_from("<I", data, 0)[0]
    compressed = data[4:]
    return lz4.block.decompress(compressed, uncompressed_size=uncompressed_size)


def compress_message(data: bytes) -> bytes:
    """LZ4 block compress with 4-byte LE uncompressed size header."""
    compressed = lz4.block.compress(data, store_size=False)
    return struct.pack("<I", len(data)) + compressed


def decrypt_and_decompress(data: bytes) -> bytes:
    """Full pipeline: decrypt then decompress."""
    decrypted = decrypt_message(data)
    return decompress_message(decrypted)


def compress_and_encrypt(data: bytes) -> bytes:
    """Full pipeline: compress then encrypt."""
    compressed = compress_message(data)
    return encrypt_message(compressed)


# ============================================================================
# FlatBuffer helpers (minimal reader/writer matching the Rust implementation)
# ============================================================================


def read_u32(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buf, offset)[0]


def read_i32(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<i", buf, offset)[0]


def read_u16(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<H", buf, offset)[0]


def read_string(buf: bytes, str_offset: int) -> str:
    """Read a FlatBuffer string at the given absolute offset."""
    length = read_u32(buf, str_offset)
    return buf[str_offset + 4 : str_offset + 4 + length].decode("utf-8")


class FlatBufferTable:
    """Minimal FlatBuffer table reader."""

    def __init__(self, buf: bytes):
        self.buf = buf
        root_off = read_u32(buf, 0)
        self.root_pos = root_off
        soffset = read_i32(buf, root_off)
        self.vt_pos = root_off - soffset
        self.vt_size = read_u16(buf, self.vt_pos)

    def num_fields(self) -> int:
        return (self.vt_size - 4) // 2

    def field_offset(self, field_id: int) -> int:
        if field_id >= self.num_fields():
            return 0
        return read_u16(self.buf, self.vt_pos + 4 + field_id * 2)

    def read_u32(self, field_id: int) -> int:
        foff = self.field_offset(field_id)
        if foff == 0:
            return 0
        return read_u32(self.buf, self.root_pos + foff)

    def read_string(self, field_id: int) -> str:
        foff = self.field_offset(field_id)
        if foff == 0:
            return ""
        rel = read_u32(self.buf, self.root_pos + foff)
        str_pos = self.root_pos + foff + rel
        return read_string(self.buf, str_pos)


class FlatBufferBuilder:
    """Minimal FlatBuffer builder matching the Rust binary layout.

    All refs are `used_space()` values — the byte count from the head at the
    time the object was created. This is consistent with the Rust builder.
    """

    def __init__(self):
        self.buf = bytearray()
        self.head = 0
        self.vtables = []  # list of used_space() positions of written vtables
        self.fields = []
        self.field_count = 0
        self.table_start = 0
        self.in_table = False
        self.min_align = 1

    def _used_space(self) -> int:
        return len(self.buf) - self.head

    def _grow(self, additional: int):
        if self.head >= additional:
            return
        needed = additional - self.head
        new_cap = 1
        while new_cap < len(self.buf) + needed:
            new_cap <<= 1
        grow_by = new_cap - len(self.buf)
        new_buf = bytearray(new_cap)
        new_buf[grow_by + self.head :] = self.buf[self.head :]
        self.head += grow_by
        self.buf = new_buf

    def _align(self, align: int):
        used = self._used_space()
        pad = (align - (used % align)) % align
        if pad > 0:
            self._grow(pad)
            self.head -= pad
            self.buf[self.head : self.head + pad] = b"\x00" * pad
        if align > self.min_align:
            self.min_align = align

    def _push_bytes(self, data: bytes):
        self._grow(len(data))
        self.head -= len(data)
        self.buf[self.head : self.head + len(data)] = data

    def _push_u8(self, v: int):
        self._push_bytes(struct.pack("<B", v))

    def _push_u16(self, v: int):
        self._push_bytes(struct.pack("<H", v))

    def _push_u32(self, v: int):
        self._push_bytes(struct.pack("<I", v))

    def _push_i32(self, v: int):
        self._push_bytes(struct.pack("<i", v))

    def create_string(self, s: str) -> int:
        """Create a string, return its ref (used_space at creation time)."""
        data = s.encode("utf-8")
        self._align(4)
        ref = self._used_space()
        self._push_u32(len(data))
        self._push_bytes(data)
        self._push_u8(0)  # null terminator
        # Pad to 4 bytes
        pad = (4 - (len(data) + 1) % 4) % 4
        if pad > 0:
            self._push_bytes(b"\x00" * pad)
        return ref

    def create_vector_u8(self, data: bytes) -> int:
        """Create a byte vector, return its ref."""
        self._align(4)
        ref = self._used_space()
        self._push_u32(len(data))
        self._push_bytes(data)
        # Pad to 4 bytes
        pad = (4 - len(data) % 4) % 4
        if pad > 0:
            self._push_bytes(b"\x00" * pad)
        return ref

    def start_table(self, field_count: int):
        self.table_start = self._used_space()
        self.field_count = field_count
        self.fields = [(0, 0)] * field_count  # (size, used_space_after_push)
        self.in_table = True

    def table_add_u32(self, field_id: int, v: int, default: int = 0):
        if v == default:
            return
        self._align(4)
        self._push_u32(v)
        self.fields[field_id] = (4, self._used_space())

    def table_add_offset(self, field_id: int, ref: int):
        """Add an offset field. `ref` is a used_space() value."""
        self._align(4)
        # Push the offset: it's the distance from this position to the ref
        # Since ref = used_space() at creation, and current used_space() is where
        # we are now, the offset = ref - current_used_space
        offset = ref - self._used_space()
        self._push_i32(offset)
        self.fields[field_id] = (4, self._used_space())

    def end_table(self) -> int:
        """End the table, return its ref (used_space at table start)."""
        # Build vtable
        vt = [0] * (self.field_count + 2)
        vt[0] = len(vt) * 2  # vtable size in bytes
        # Table size: from soffset to end of last field
        max_field_end = 0
        for size, pos in self.fields:
            if pos > max_field_end:
                max_field_end = pos
        vt[1] = max_field_end - self.table_start + 4  # +4 for soffset

        for field_id, (size, pos) in enumerate(self.fields):
            if size > 0:
                vt[2 + field_id] = pos - self.table_start

        # Check for vtable dedup
        vt_bytes = struct.pack(f"<{len(vt)}H", *vt)
        vtable_ref = None
        for vc_ref in self.vtables:
            vc_abs = len(self.buf) - vc_ref
            stored_vt = self.buf[
                vc_abs - self.head : vc_abs - self.head + len(vt_bytes)
            ]
            if bytes(stored_vt) == vt_bytes:
                vtable_ref = vc_ref
                break

        if vtable_ref is None:
            self._align(4)
            vtable_ref = self._used_space()
            self._push_bytes(vt_bytes)
            self.vtables.append(vtable_ref)

        # Write soffset: distance from current position to vtable
        self._align(4)
        soffset = self._used_space() - vtable_ref
        self._push_i32(soffset)

        self.in_table = False
        return self.table_start  # Return used_space at table start

    def finish_minimal(self, root_ref: int) -> bytes:
        """Finish the buffer, prepend root offset, return bytes."""
        align = max(self.min_align, 4)
        used = self._used_space()
        total = 4 + used
        padded_total = (total + align - 1) & ~(align - 1)
        pad = padded_total - total
        if pad > 0:
            self._grow(pad)
            self.head -= pad
            self.buf[self.head : self.head + pad] = b"\x00" * pad

        # root_ref is a used_space() value. The absolute position of the root
        # table in the buffer is: len(self.buf) - root_ref
        root_abs = len(self.buf) - root_ref
        # The offset from byte 0 to the root table
        root_offset = root_abs - self.head
        self._push_u32(root_offset)

        return bytes(self.buf[self.head :])


def parse_outer_wrapper(data: bytes) -> tuple:
    """Parse outer wrapper: { type: u32 (field 0), payload: [ubyte] (field 1) }"""
    tbl = FlatBufferTable(data)
    msg_type = tbl.read_u32(0)
    # Read payload vector
    payload_foff = tbl.field_offset(1)
    if payload_foff == 0:
        return msg_type, b""
    rel = read_u32(data, tbl.root_pos + payload_foff)
    vec_pos = tbl.root_pos + payload_foff + rel
    vec_len = read_u32(data, vec_pos)
    payload = data[vec_pos + 4 : vec_pos + 4 + vec_len]
    return msg_type, payload


def build_create_response(
    entry_id: int, timestamp: int, entry_type: str, author: str
) -> bytes:
    """Build a CreateEntry response FlatBuffer.

    EXACTLY matches the Rust server implementation:
    Inner table (5 fields):
      field 0: entry_id (u32)
      field 1: timestamp (u32)
      field 3: entry_type (string)  <-- field 3, NOT 2
      field 4: author (string)       <-- field 4, NOT 3
    """
    ib = FlatBufferBuilder()
    et_ref = ib.create_string(entry_type)
    au_ref = ib.create_string(author)
    ib.start_table(5)
    ib.table_add_u32(0, entry_id, 0)
    ib.table_add_u32(1, timestamp, 0)
    ib.table_add_offset(3, et_ref)  # field 3, matching Rust server
    ib.table_add_offset(4, au_ref)  # field 4, matching Rust server
    inner_root = ib.end_table()
    inner_bytes = ib.finish_minimal(inner_root)

    log.debug(f"  [FB] Inner bytes ({len(inner_bytes)}B): {inner_bytes.hex()}")

    # Build outer wrapper
    ob = FlatBufferBuilder()
    payload_ref = ob.create_vector_u8(inner_bytes)
    ob.start_table(2)
    ob.table_add_u32(0, 3, 0)  # type = 3 (CreateEntry response)
    ob.table_add_offset(1, payload_ref)
    wrapper_root = ob.end_table()
    outer_bytes = ob.finish_minimal(wrapper_root)
    log.debug(f"  [FB] Outer bytes ({len(outer_bytes)}B): {outer_bytes.hex()}")
    return outer_bytes


def build_update_response(
    entry_id: int, timestamp: int, entry_type: str, author: str
) -> bytes:
    """Build an UpdateEntry response FlatBuffer (same structure as CreateEntry)."""
    return build_create_response(entry_id, timestamp, entry_type, author)


# ============================================================================
# Filesystem helpers
# ============================================================================


def ensure_directories():
    """Create nl/, nl/scripts/, nl/configs/, nl/langs/ if they don't exist."""
    NL_DIR.mkdir(parents=True, exist_ok=True)
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    LANGS_DIR.mkdir(parents=True, exist_ok=True)


def save_script(entry_id: int, name: str, content: str = "") -> Path:
    """Save a script to nl/scripts/{entry_id}_{name}.lua"""
    safe_name = "".join(c if c.isalnum() or c in " _-" else "_" for c in name)
    filename = f"{entry_id}_{safe_name}.lua"
    filepath = SCRIPTS_DIR / filename
    filepath.write_text(content, encoding="utf-8")
    log.info(f"  [FS] Saved script: {filepath} ({len(content)} bytes)")
    return filepath


def update_script(entry_id: int, name: str, content: str) -> Path:
    """Update an existing script or create a new one."""
    # Find existing file by entry_id prefix
    for f in SCRIPTS_DIR.iterdir():
        if f.name.startswith(f"{entry_id}_"):
            safe_name = "".join(c if c.isalnum() or c in " _-" else "_" for c in name)
            new_filename = f"{entry_id}_{safe_name}.lua"
            new_path = SCRIPTS_DIR / new_filename
            f.write_text(content, encoding="utf-8")
            if f.name != new_filename:
                f.rename(new_path)
                log.info(f"  [FS] Renamed and updated script: {new_path}")
            else:
                log.info(f"  [FS] Updated script: {f}")
            return new_path
    # Not found, create new
    return save_script(entry_id, name, content)


def save_config(entry_id: int, name: str, content: str = "") -> Path:
    """Save a config to nl/configs/{entry_id}_{name}.json"""
    safe_name = "".join(c if c.isalnum() or c in " _-" else "_" for c in name)
    filename = f"{entry_id}_{safe_name}.json"
    filepath = CONFIGS_DIR / filename
    filepath.write_text(content, encoding="utf-8")
    log.info(f"  [FS] Saved config: {filepath} ({len(content)} bytes)")
    return filepath


def update_config(entry_id: int, name: str, content: str) -> Path:
    """Update an existing config or create a new one."""
    for f in CONFIGS_DIR.iterdir():
        if f.name.startswith(f"{entry_id}_"):
            safe_name = "".join(c if c.isalnum() or c in " _-" else "_" for c in name)
            new_filename = f"{entry_id}_{safe_name}.json"
            new_path = CONFIGS_DIR / new_filename
            f.write_text(content, encoding="utf-8")
            if f.name != new_filename:
                f.rename(new_path)
                log.info(f"  [FS] Renamed and updated config: {new_path}")
            else:
                log.info(f"  [FS] Updated config: {f}")
            return new_path
    return save_config(entry_id, name, content)


def save_language(code: str, translations: dict) -> Path:
    """Save a language file to nl/langs/{code}.json"""
    filepath = LANGS_DIR / f"{code}.json"
    filepath.write_text(
        json.dumps(translations, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    log.info(f"  [FS] Saved language: {filepath}")
    return filepath


# ============================================================================
# Message handlers
# ============================================================================


async def handle_create_entry(state: dict, inner_payload: bytes) -> bytes:
    """Handle CreateEntry message (type=3).

    The client sends CreateEntry with name, entry_type, and expected_count.
    expected_count is the total number of entries including this new one,
    so the entry_id should equal expected_count.
    """
    tbl = FlatBufferTable(inner_payload)
    name = tbl.read_string(0)
    entry_type = tbl.read_u32(1)
    expected_count = tbl.read_u32(2)

    type_str = "Script" if entry_type == 1 else "Config"
    # Use expected_count as the entry_id - this is the sequential ID the client expects
    entry_id = expected_count
    timestamp = int(time.time())
    author = "user"

    log.info(
        f"  [Handler] CreateEntry: name={name!r} type={type_str} expected_count={expected_count} entry_id={entry_id}"
    )

    # Save to filesystem
    if entry_type == 1:
        save_script(entry_id, name, f"-- {name}\n-- Created by neverlose\n")
    else:
        save_config(
            entry_id, name, json.dumps({"name": name, "settings": {}}, indent=2)
        )

    # Update MODULE_DATA with new entry
    entry = {
        "entry_id": entry_id,
        "timestamp": timestamp,
        "name": name,
        "author": author,
    }
    if entry_type == 1:
        MODULE_DATA["script_entries"].append(entry)
    else:
        MODULE_DATA["config_entries"].append(entry)

    # Rebuild module for future connections
    rebuild_module()

    # Build response - match Rust server exactly
    response = build_create_response(entry_id, timestamp, type_str, author)

    # Debug: dump the raw response before encryption
    log.info(f"  [Handler] Response: {len(response)} bytes raw, hex: {response.hex()}")
    return compress_and_encrypt(response)


async def handle_update_entry(state: dict, inner_payload: bytes) -> bytes:
    """Handle UpdateEntry message (type=1)."""
    tbl = FlatBufferTable(inner_payload)
    entry_id = tbl.read_u32(0)
    entry_type = tbl.read_u32(1)

    # Read optional fields
    content = tbl.read_string(2)
    name = tbl.read_string(3)
    timestamp = tbl.read_u32(4)
    if timestamp == 0:
        timestamp = int(time.time())

    type_str = "Script" if entry_type == 1 else "Config"
    log.info(
        f"  [Handler] UpdateEntry: entry_id={entry_id} type={type_str} name={name!r} content_len={len(content) if content else 0} ts={timestamp}"
    )

    # Update filesystem
    if entry_type == 1 and content:
        if name:
            update_script(entry_id, name, content)
        else:
            # Try to find existing script and update its content
            for f in SCRIPTS_DIR.iterdir():
                if f.name.startswith(f"{entry_id}_"):
                    f.write_text(content, encoding="utf-8")
                    log.info(f"  [FS] Updated script content: {f}")
                    break
    elif entry_type == 0 and content:
        if name:
            update_config(entry_id, name, content)
        else:
            for f in CONFIGS_DIR.iterdir():
                if f.name.startswith(f"{entry_id}_"):
                    f.write_text(content, encoding="utf-8")
                    log.info(f"  [FS] Updated config content: {f}")
                    break

    # Update MODULE_DATA timestamp
    for entry in MODULE_DATA.get("script_entries", []) + MODULE_DATA.get(
        "config_entries", []
    ):
        if entry["entry_id"] == entry_id:
            entry["timestamp"] = timestamp
            if name:
                entry["name"] = name
            break

    # Rebuild module for future connections
    rebuild_module()

    # Build response
    response = build_update_response(entry_id, timestamp, type_str, "user")
    return compress_and_encrypt(response)


async def handle_init(state: dict, inner_payload: bytes):
    """Handle Init message (type=0)."""
    tbl = FlatBufferTable(inner_payload)
    steam_id = tbl.read_string(0)
    log.info(f"  [Handler] Init: steam_id={steam_id!r}")


async def handle_config_ack(state: dict, inner_payload: bytes):
    """Handle ConfigAck message (type=10)."""
    tbl = FlatBufferTable(inner_payload)
    entry_id = tbl.read_u32(0)
    log.info(f"  [Handler] ConfigAck: entry_id={entry_id}")


# ============================================================================
# WebSocket handler
# ============================================================================


async def handle_client(ws):
    addr = ws.remote_address
    log.info(f"[+] Connection from {addr[0]}:{addr[1]}")
    msg_num = 0

    try:
        # Wait for client's first message before sending anything
        first_msg = await ws.recv()
        timestamp = time.time()
        msg_num += 1

        if isinstance(first_msg, str):
            log.info(f"  [C->S] #{msg_num} text ({len(first_msg)}B): {first_msg[:200]}")
            MSG_LOG.append(
                {"dir": "C->S", "type": "text", "data": first_msg, "time": timestamp}
            )
        else:
            log.info(
                f"  [C->S] #{msg_num} binary ({len(first_msg)}B): {first_msg[:32].hex()}"
            )
            MSG_LOG.append(
                {
                    "dir": "C->S",
                    "type": "binary",
                    "size": len(first_msg),
                    "hex": first_msg[:64].hex(),
                    "time": timestamp,
                }
            )

        # Frame 1: Auth JSON
        auth = json.dumps({"Type": "Auth", "Message": AUTH_MESSAGE, "Data": AUTH_DATA})
        await ws.send(auth)
        log.info(f"  [S->C] Auth JSON ({len(auth)}B): {auth}")

        # Frame 2: Module payload (dynamically built with filesystem entries)
        module_to_send = (
            current_module_encrypted if current_module_encrypted else ORIGINAL_MODULE
        )
        await ws.send(module_to_send)
        log.info(f"  [S->C] Module blob ({len(module_to_send):,}B)")

        # Frame 3: Encrypted key material
        await ws.send(KEY_BLOB)
        log.info(f"  [S->C] Key blob ({len(KEY_BLOB)}B): {KEY_BLOB.hex()}")

        log.info(f"  [S->C] All 3 frames sent, listening for client messages...")

        # Process client messages
        async for msg in ws:
            timestamp = time.time()
            msg_num += 1

            if isinstance(msg, str):
                log.info(f"  [C->S] #{msg_num} text ({len(msg)}B): {msg[:200]}")
                MSG_LOG.append(
                    {"dir": "C->S", "type": "text", "data": msg, "time": timestamp}
                )
                continue

            # Binary message — try to decrypt, decompress, and handle
            log.info(f"  [C->S] #{msg_num} binary ({len(msg)}B): {msg[:32].hex()}...")
            MSG_LOG.append(
                {
                    "dir": "C->S",
                    "type": "binary",
                    "size": len(msg),
                    "hex": msg[:64].hex(),
                    "time": timestamp,
                }
            )

            try:
                # Decrypt and decompress
                decompressed = decrypt_and_decompress(msg)
                log.info(f"  [Decrypt] OK ({len(decompressed)}B decompressed)")

                # Parse outer wrapper
                msg_type, inner_payload = parse_outer_wrapper(decompressed)
                log.info(
                    f"  [Parse] type={msg_type}, inner_payload={len(inner_payload)}B"
                )

                # Handle based on type
                state = {}
                response = None

                if msg_type == 0:
                    await handle_init(state, inner_payload)
                elif msg_type == 10:
                    await handle_config_ack(state, inner_payload)
                elif msg_type == 3:
                    response = await handle_create_entry(state, inner_payload)
                elif msg_type == 1:
                    response = await handle_update_entry(state, inner_payload)
                else:
                    log.info(f"  [Handler] Unknown type {msg_type}")

                # Send response if any
                if response:
                    await ws.send(response)
                    log.info(f"  [S->C] Response ({len(response)}B encrypted)")

            except Exception as e:
                log.warning(f"  [Decrypt/Parse] Failed: {e}")
                # Log the raw message for debugging
                log.debug(f"  [Raw hex] {msg[:128].hex()}")

    except websockets.ConnectionClosed as e:
        log.info(f"  [!] Connection closed: code={e.code} reason={e.reason}")
    except Exception as e:
        log.error(f"  [!] Error: {e}")

    log.info(f"[-] Disconnected {addr[0]}:{addr[1]} (total messages: {msg_num})")


def generate_cert():
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    log.info("Generating self-signed TLS certificate...")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        KEY_FILE.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    except ImportError:
        import subprocess

        ret = os.system(
            f'openssl req -x509 -newkey rsa:2048 -keyout "{KEY_FILE}" -out "{CERT_FILE}" '
            f'-days 365 -nodes -subj "/CN=127.0.0.1" 2>/dev/null'
        )
        if ret != 0:
            print("Failed to generate TLS certificate.")
            print("Install the 'cryptography' package: pip install cryptography")
            sys.exit(1)


async def main():
    generate_cert()
    ensure_directories()

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE)

    async with websockets.serve(
        handle_client,
        HOST,
        PORT,
        ssl=ssl_ctx,
        max_size=50 * 1024 * 1024,
        ping_interval=None,
    ):
        log.info(f"Neverlose WSS server on wss://{HOST}:{PORT}/")
        log.info(f"  Auth Message: {AUTH_MESSAGE}")
        log.info(f"  Auth Data:    {AUTH_DATA}")
        log.info(f"  Original module:  {len(ORIGINAL_MODULE):,} bytes")
        log.info(f"  Dynamic module:   rebuilt on each connection")
        log.info(f"  Key blob:     {len(KEY_BLOB)} bytes")
        log.info(f"  NL directory: {NL_DIR}")
        log.info(f"  Scripts dir:  {SCRIPTS_DIR}")
        log.info(f"  Configs dir:  {CONFIGS_DIR}")
        log.info(f"  Langs dir:    {LANGS_DIR}")
        log.info("")
        log.info("Protocol (enhanced with full message handling):")
        log.info("  1. Client connects via WSS")
        log.info("  2. Server waits for client's first message (any content)")
        log.info("  3. Server sends: Auth JSON + module blob + key blob")
        log.info("  4. Server processes client binary messages:")
        log.info("     - Type 0: Init (steam_id)")
        log.info(
            "     - Type 1: UpdateEntry (entry_id, type, content, name, timestamp)"
        )
        log.info("     - Type 3: CreateEntry (name, type, expected_count)")
        log.info("     - Type 10: ConfigAck (entry_id)")
        log.info(
            "  5. Server responds with encrypted FlatBuffer for CreateEntry/UpdateEntry"
        )
        log.info("")
        log.info("Filesystem:")
        log.info(f"  Scripts  -> {SCRIPTS_DIR}/")
        log.info(f"  Configs  -> {CONFIGS_DIR}/")
        log.info(f"  Languages -> {LANGS_DIR}/")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
