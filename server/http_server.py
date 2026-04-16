#!/usr/bin/env python3
"""
Neverlose HTTP Server - Port 30031

Replicates the Express.js HTTP server for the Neverlose binary.
This handles MakeRequest (vtable slot 0) and QueryLuaLibrary (vtable slot 4) calls.
WebSocket-based fn3 (vtable slot 3) and GetSerial (vtable slot 1) are handled by wss_server.py.

Discovered routes (via static XOR decryption of nl.bin):
  GET /api/config                                    - Client config (404 on crack server)
  GET /api/getavatar?size=100&token=<TOKEN>           - User avatar (ONLY working HTTP route on crack server)
  GET /api/sendlog?token=T&a=0&build=B&cont=C&dump=D&cheat=csgo - Crash log (404 on crack server)
  GET /lua/<name>?token=T&cheat=csgo&build=B         - Lua library fetch (404 on crack server)

Crack server probe results (2026-02-22):
  - Only /api/getavatar returns 200 (PNG image, ~19-29KB depending on size param)
  - All other routes return Express-style 404
  - Token param is ignored (works without it)
  - Server header: X-Powered-By: Express

Usage:
  nix-shell -p python3 --run "python3 server/http_server.py"
"""

import json
import sys
import logging
import os
import re
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

HOST = "0.0.0.0"
PORT = 30031

# Working directory: nl/ (located in CS:GO game directory)
NL_DIR = Path(r"C:\Program Files (x86)\Steam\steamapps\common\csgo legacy\nl")
SCRIPTS_DIR = NL_DIR / "scripts"
CONFIGS_DIR = NL_DIR / "configs"
LANGS_DIR = NL_DIR / "langs"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("http")

# Spoofed serial (from Requestor.cpp)
SPOOFED_SERIAL = (
    "g6w/cgN2AuDsLw3xrzboM1kbkLy+osvg0Y/j0LJnQf04GHbV8s5V4yReEk1mh3ZA"
    "2G72fHG3oOh7zlGEfR1nKw717WiwRwsrgSDfJtaTQz14VDDkayLBNV1DaT/qSyx8Fr"
    "g1nXU0crRu1P/G+EPvH6nWNPYLZdUMIeqVCToEFhJnqiuRoAyypjFNiKnLEMiy5j2"
    "YvBcLCOC8yC3FPt/GGsvUldBqkmQGkBjIsXsSkut05txVxq7VDx1i9adKE4zalTzNH"
    "r0Vtd6DTr8aeH8NYHWPGWAsnTBkZlkNuRuhBTtgRTcIKxzGATTN4k8/JaXCpxri7Iq"
    "sylvZgXQw+5zldLjAHqcAWw3OD5iQn8DtOoon+DrHm3k3FY6wIrCM1FzTdjAIcTvXS"
    "iWOURHiwA4sJ8ExR4dyBZMydo8aBAYjrRxcD9oDa/VVJT4cZfDkyWvRjI3WMyEajF2"
    "JhiGcjpjztmD8fyt9C16VXwLfoYuJnrX1/Dv8SZfCU6U2UhwJlxO5mkg+/IctveCd"
    "xy8IIiXTKwA5vmiEpXRuUu17SCdmJhFLZ+Jr6cTmrob4exSEggGRk6BTaVomOq4I6I"
    "pkVUBIUVup+4JvWFseL5UkPOQqHIO5Rxnj1jY+PjAWFPeeXSZsP8/ceEnX8J13tfb"
    "7PAqRSrpQ1Wv/y+OjaqMoPg9PiRE="
)

# Request log for analysis
REQUEST_LOG = []

# Lua scripts directory (serve from here if available)
LUA_DIR = Path(__file__).parent / "lua"

# Avatar image (dumped from crack server at 145.239.80.134:30031)
DATA_DIR = Path(__file__).parent / "data"
ANALYSIS_DIR = Path(__file__).parent.parent / "analysis" / "output"
AVATAR_FILE = DATA_DIR / "avatar.png"


def _load_reqitem_candidate_keys():
    keys = set()
    ident = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

    try:
        phase1 = ANALYSIS_DIR / "phase1_results.json"
        if phase1.exists():
            data = json.loads(phase1.read_text(encoding="utf-8"))
            for item in data.get("string_categories", {}).get("possible_field_name", []):
                s = item.get("string", "")
                if ident.match(s):
                    keys.add(s)
    except Exception as e:
        log.warning(f"Failed to load reqitem candidate keys from phase1_results.json: {e}")

    try:
        decrypted = ANALYSIS_DIR / "all_decrypted_strings.json"
        if decrypted.exists():
            data = json.loads(decrypted.read_text(encoding="utf-8"))
            for item in data.get("all_strings", []):
                s = item.get("string", "")
                if ident.match(s):
                    keys.add(s)
    except Exception as e:
        log.warning(f"Failed to load reqitem candidate keys from all_decrypted_strings.json: {e}")

    return keys


REQITEM_CANDIDATE_BOOL_KEYS = _load_reqitem_candidate_keys()


class NLRequestHandler(BaseHTTPRequestHandler):
    server_version = "Express"

    def log_message(self, format, *args):
        pass

    def _log_request(self, method):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        body = None
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            raw = self.rfile.read(content_length)
            try:
                body = json.loads(raw)
            except Exception:
                body = raw.hex() if len(raw) < 1024 else f"<{len(raw)} bytes>"

        entry = {
            "method": method,
            "path": parsed.path,
            "query": params,
            "headers": dict(self.headers),
            "body": body,
            "user_agent": self.headers.get("User-Agent", ""),
            "timestamp": time.time(),
        }
        REQUEST_LOG.append(entry)

        log.info(f"  {method} {self.path}")
        if params:
            log.info(f"    params: {params}")
        if body:
            log.info(f"    body: {json.dumps(body) if isinstance(body, dict) else body}")

        return parsed, params, body

    def _send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")
        self.send_header("Connection", "keep-alive")
        self.send_header("Keep-Alive", "timeout=5")
        self.end_headers()
        self.wfile.write(body)

    def _send_json_string(self, code, text):
        body = json.dumps(text).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")
        self.send_header("Connection", "keep-alive")
        self.send_header("Keep-Alive", "timeout=5")
        self.end_headers()
        self.wfile.write(body)

    def _send_lua_module_json(self, code, name, content, found=True):
        # The client treats /api/reqitem as a JSON object and probes several
        # fields through nlohmann::json. The exact field set used by the packed
        # binary is still opaque, so return the Lua source under multiple common
        # names plus a broad boolean surface to avoid null->bool crashes.
        payload = {
            "status": "ok",
            "name": name,
            "code": content,
            "data": content,
            "body": content,
            "content": content,
            "script": content,
            "lua": content,
            "source": content,
            "module": content,
        }
        bool_fields = {
            "success": True,
            "ok": True,
            "found": found,
            "exists": found,
            "valid": True,
            "enabled": True,
            "loaded": True,
            "ready": True,
            "cached": False,
            "cache": False,
            "update": False,
            "updated": False,
            "error": False,
            "failed": False,
            "invalid": False,
            "expired": False,
            "blocked": False,
            "premium": True,
            "default": False,
            "builtin": True,
            "is_success": True,
            "is_ok": True,
            "is_found": found,
            "is_valid": True,
            "is_enabled": True,
            "is_loaded": True,
            "is_ready": True,
            "is_cached": False,
            "is_cache": False,
            "is_update": False,
            "is_updated": False,
            "is_error": False,
            "is_failed": False,
            "is_invalid": False,
            "is_expired": False,
            "is_blocked": False,
            "is_premium": True,
            "is_default": False,
            "is_builtin": True,
            "has_data": True,
            "has_code": True,
            "has_script": True,
            "has_lua": True,
            "has_module": True,
            "has_content": True,
            "has_body": True,
            "has_source": True,
            "has_error": False,
            "has_update": False,
            "need_update": False,
            "needs_update": False,
            "require_update": False,
            "requires_update": False,
            "allow_update": False,
            "allow_load": True,
            "can_load": True,
            "can_use": True,
            "can_run": True,
            "can_execute": True,
            "available": True,
            "present": found,
            "active": True,
            "alive": True,
            "public": True,
            "private": False,
            "free": True,
            "pro": True,
            "vip": True,
            "beta": False,
            "debug": False,
            "release": True,
            "Error": False,
            "Success": True,
            "Update": False,
            "Updated": False,
            "Found": found,
            "Valid": True,
            "Enabled": True,
            "Loaded": True,
            "Ready": True,
            "Cached": False,
            "Premium": True,
            "Builtin": True,
        }
        for key in REQITEM_CANDIDATE_BOOL_KEYS:
            payload.setdefault(key, False)
            payload.setdefault(key.lower(), False)
            payload.setdefault(key.upper(), False)
            payload.setdefault(key[:1].upper() + key[1:], False)
            if key and key[0].islower():
                payload.setdefault(f"is_{key}", False)
                payload.setdefault(f"has_{key}", False)
                payload.setdefault(f"can_{key}", False)
                payload.setdefault(f"need_{key}", False)
                payload.setdefault(f"requires_{key}", False)
        payload.update(bool_fields)
        self._send_json(code, payload)

    def _send_text(self, code, text):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")
        self.send_header("Connection", "keep-alive")
        self.send_header("Keep-Alive", "timeout=5")
        self.end_headers()
        self.wfile.write(body)

    def _send_binary(self, code, data, content_type="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "Express")
        self.send_header("Connection", "keep-alive")
        self.send_header("Keep-Alive", "timeout=5")
        self.end_headers()
        self.wfile.write(data)

    def _send_express_404(self, method):
        html = (
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
            "<meta charset=\"utf-8\">\n<title>Error</title>\n"
            "</head>\n<body>\n"
            f"<pre>Cannot {method} {self.path}</pre>\n"
            "</body>\n</html>\n"
        )
        body = html.encode()
        self.send_response(404)
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")
        self.send_header("Connection", "keep-alive")
        self.send_header("Keep-Alive", "timeout=5")
        self.end_headers()
        self.wfile.write(body)

    def _ensure_nl_dirs(self):
        """Create nl/, nl/scripts/, nl/configs/, nl/langs/ if they don't exist."""
        NL_DIR.mkdir(parents=True, exist_ok=True)
        SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
        CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
        LANGS_DIR.mkdir(parents=True, exist_ok=True)

    def _route(self, method):
        parsed, params, body = self._log_request(method)
        path = parsed.path.rstrip("/") or "/"
        token = params.get("token", [None])[0]
        cheat = params.get("cheat", [None])[0]
        build = params.get("build", [None])[0]

        # =====================================================================
        # Route: /api/config
        # Source: Confirmed via Unicorn emulation (vtable_site1_MakeRequest)
        # Caller: Function 0x415890C0 via MakeRequest (vtable slot 0)
        # The client fetches initial configuration on startup.
        # =====================================================================
        if path == "/api/config":
            log.info("    -> MakeRequest(/api/config)")
            self._send_json(200, {
                "status": "ok",
                "version": "2.0",
                "update": False,
                "config": {
                    "glow": True,
                    "esp": True,
                    "aimbot": True,
                    "misc": True,
                },
            })
            return

        # =====================================================================
        # Route: /api/getavatar
        # Source: XOR decryption of function 0x415890C0
        # Caller: MakeRequest (vtable slot 0)
        # Full route: api/getavatar?size=100&token=<TOKEN>
        # Response: Avatar image data (PNG/JPEG) or URL
        # The function also references JSON fields: Message, Sender, Type, Time, Msg
        # suggesting the response may include chat message data alongside avatar.
        # =====================================================================
        if path in ("/api/getavatar", "/getavatar"):
            size = params.get("size", ["100"])[0]
            log.info(f"    -> MakeRequest(/api/getavatar, size={size}, token={token})")
            # Serve the real avatar dumped from crack server
            if AVATAR_FILE.exists():
                avatar_data = AVATAR_FILE.read_bytes()
                self._send_binary(200, avatar_data, "image/png")
            else:
                # Fallback: minimal 1x1 transparent PNG
                png_1x1 = (
                    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
                    b'\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
                    b'\x00\x00\x00\nIDATx\x9cb\x00\x00\x00\x02\x00\x01'
                    b"\xe5'\xde\xfc\x00\x00\x00\x00IEND\xaeB`\x82"
                )
                self._send_binary(200, png_1x1, "image/png")
            return

        # =====================================================================
        # Route: /api/sendlog
        # Source: XOR decryption of function 0x415ECC45
        # Caller: fn3 (vtable slot 3) — but sends HTTP request
        # Full route: api/sendlog?token=T&a=0&build=B&cont=C&dump=D&cheat=csgo
        # The dump parameter contains register values (eax=, ebp=, etc.)
        # This is the crash/error reporting endpoint.
        # =====================================================================
        if path in ("/api/sendlog", "/sendlog"):
            a = params.get("a", [None])[0]
            cont = params.get("cont", [None])[0]
            dump = params.get("dump", [None])[0]
            log.info(f"    -> api/sendlog (token={token}, a={a}, build={build}, "
                     f"cont={cont}, dump={dump}, cheat={cheat})")
            self._send_json(200, {"status": "ok"})
            return

        # =====================================================================
        # Route: /api/reqitem?name=<module_name>
        # Source: QueryLuaLibrary via MakeRequest
        # This is the actual route used by require("neverlose/pui")
        # Client expects JSON response with lua code inside
        #
        # CRITICAL: The binary parses this response with nlohmann::json and
        # accesses boolean fields. The /api/config response (which works) has
        # "update": false. The binary likely checks "update" on ALL MakeRequest
        # responses. Missing boolean fields cause:
        #   [json.exception.type_error.302] type must be boolean, but is null
        #
        # We include all plausible boolean fields to ensure the binary finds
        # whichever one it expects. Extra fields are harmless.
        # =====================================================================
        if path in ("/api/reqitem", "/reqitem"):
            name = params.get("name", [None])[0]
            if name:
                log.info(f"    -> api/reqitem (name={name})")

                # Prefer compact repo-local stubs first. Large real libraries
                # from nl/ can exceed the client string path's safe payload size
                # and crash during cleanup on this build.
                content = None
                if not name.endswith(".lua"):
                    if "/" not in name:
                        lua_file = LUA_DIR / "neverlose" / f"{name}.lua"
                    else:
                        lua_file = LUA_DIR / f"{name}.lua"
                else:
                    lua_file = LUA_DIR / name

                if lua_file.exists():
                    content = lua_file.read_text()
                    log.info(f"    -> Serving stub {lua_file} ({len(content)} bytes)")
                else:
                    nl_lua_file = NL_DIR / f"{name}.lua"
                    if nl_lua_file.exists():
                        content = nl_lua_file.read_text()
                        log.info(f"    -> Serving from nl/ {nl_lua_file} ({len(content)} bytes)")
                    else:
                        log.warning(f"    -> Module not found: {name}")
                        content = (
                            "local mt={}\n"
                            "local function node() return setmetatable({}, mt) end\n"
                            "mt.__index=function() return node() end\n"
                            "mt.__call=function() return node() end\n"
                            f"return setmetatable({{}}, mt) -- {name}\n"
                        )

                self._send_lua_module_json(200, name, content, found=True)
            else:
                self._send_json(400, {"error": "name parameter required",
                                      "success": False, "update": False})
            return

        # =====================================================================
        # Route: /lua/<name>
        # Source: QueryLuaLibrary (vtable slot 4)
        # Caller: Various lua script loading functions
        # The client requests lua libraries by name.
        # Requestor.cpp returns the library name as-is (placeholder).
        # =====================================================================
        if path.startswith("/lua/"):
            libname = path[5:]
            log.info(f"    -> QueryLuaLibrary({libname})")

            lua_file = LUA_DIR / f"{libname}.lua"
            if lua_file.exists():
                content = lua_file.read_text()
                log.info(f"    -> Serving stub {lua_file} ({len(content)} bytes)")
                self._send_text(200, content)
                return

            nl_lua_file = NL_DIR / f"{libname}.lua"
            if nl_lua_file.exists():
                content = nl_lua_file.read_text()
                log.info(f"    -> Serving from nl/ {nl_lua_file} ({len(content)} bytes)")
                self._send_text(200, content)
            else:
                self._send_text(200, f"-- lua library: {libname}\n")
            return

        # =====================================================================
        # Route: /api/scripts
        # Serve scripts from nl/scripts/ directory
        # =====================================================================
        if path in ("/api/scripts", "/scripts"):
            self._ensure_nl_dirs()
            log.info("    -> /api/scripts (listing scripts)")
            scripts = []
            for f in sorted(SCRIPTS_DIR.iterdir()):
                if f.is_file():
                    scripts.append({
                        "name": f.stem,
                        "filename": f.name,
                        "size": f.stat().st_size,
                        "modified": f.stat().st_mtime
                    })
            self._send_json(200, {"scripts": scripts})
            return

        # =====================================================================
        # Route: /api/scripts/<name>
        # Get or create a specific script
        # =====================================================================
        if path.startswith("/api/scripts/"):
            self._ensure_nl_dirs()
            script_name = path[len("/api/scripts/"):]
            if method == "GET":
                log.info(f"    -> /api/scripts/{script_name} (GET)")
                script_file = SCRIPTS_DIR / f"{script_name}.lua"
                if not script_file.exists():
                    script_file = SCRIPTS_DIR / script_name
                if script_file.exists():
                    self._send_text(200, script_file.read_text())
                else:
                    self._send_json(404, {"error": "Script not found"})
                return
            elif method == "POST":
                log.info(f"    -> /api/scripts/{script_name} (POST)")
                content = body if isinstance(body, str) else (body.get("content", "") if isinstance(body, dict) else "")
                script_file = SCRIPTS_DIR / f"{script_name}.lua"
                if not script_file.exists():
                    script_file = SCRIPTS_DIR / script_name
                script_file.write_text(str(content))
                self._send_json(200, {"status": "ok", "path": str(script_file)})
                return

        # =====================================================================
        # Route: /api/configs
        # Serve configs from nl/configs/ directory
        # =====================================================================
        if path in ("/api/configs", "/configs"):
            self._ensure_nl_dirs()
            log.info("    -> /api/configs (listing configs)")
            configs = []
            for f in sorted(CONFIGS_DIR.iterdir()):
                if f.is_file():
                    configs.append({
                        "name": f.stem,
                        "filename": f.name,
                        "size": f.stat().st_size,
                        "modified": f.stat().st_mtime
                    })
            self._send_json(200, {"configs": configs})
            return

        # =====================================================================
        # Route: /api/configs/<name>
        # Get or create a specific config
        # =====================================================================
        if path.startswith("/api/configs/"):
            self._ensure_nl_dirs()
            config_name = path[len("/api/configs/"):]
            if method == "GET":
                log.info(f"    -> /api/configs/{config_name} (GET)")
                config_file = CONFIGS_DIR / f"{config_name}.json"
                if not config_file.exists():
                    config_file = CONFIGS_DIR / config_name
                if config_file.exists():
                    self._send_text(200, config_file.read_text())
                else:
                    self._send_json(404, {"error": "Config not found"})
                return
            elif method == "POST":
                log.info(f"    -> /api/configs/{config_name} (POST)")
                content = body if isinstance(body, str) else (body.get("content", "") if isinstance(body, dict) else "")
                config_file = CONFIGS_DIR / f"{config_name}.json"
                if not config_file.exists():
                    config_file = CONFIGS_DIR / config_name
                config_file.write_text(str(content))
                self._send_json(200, {"status": "ok", "path": str(config_file)})
                return

        # =====================================================================
        # Route: /api/langs
        # Serve languages from nl/langs/ directory
        # =====================================================================
        if path in ("/api/langs", "/langs"):
            self._ensure_nl_dirs()
            log.info("    -> /api/langs (listing languages)")
            langs = []
            for f in sorted(LANGS_DIR.iterdir()):
                if f.is_file() and f.suffix == ".json":
                    try:
                        data = json.loads(f.read_text())
                        langs.append({
                            "code": f.stem,
                            "filename": f.name,
                            "info": data.get("info", {}),
                            "string_count": len(data.get("strings", {}))
                        })
                    except Exception as e:
                        langs.append({"code": f.stem, "filename": f.name, "error": str(e)})
            self._send_json(200, {"languages": langs})
            return

        # =====================================================================
        # Route: /api/langs/<code>
        # Get or create a specific language
        # =====================================================================
        if path.startswith("/api/langs/"):
            self._ensure_nl_dirs()
            lang_code = path[len("/api/langs/"):]
            if method == "GET":
                log.info(f"    -> /api/langs/{lang_code} (GET)")
                lang_file = LANGS_DIR / f"{lang_code}.json"
                if not lang_file.exists():
                    lang_file = LANGS_DIR / lang_code
                if lang_file.exists():
                    self._send_text(200, lang_file.read_text())
                else:
                    self._send_json(404, {"error": "Language not found"})
                return
            elif method == "POST":
                log.info(f"    -> /api/langs/{lang_code} (POST)")
                content = body if isinstance(body, dict) else {}
                lang_file = LANGS_DIR / f"{lang_code}.json"
                lang_file.write_text(json.dumps(content, indent=2, ensure_ascii=False))
                self._send_json(200, {"status": "ok", "path": str(lang_file)})
                return

        # =====================================================================
        # Route: POST with JSON body (GetSerial fallback)
        # Source: Requestor.cpp GetSerial function
        # The client may POST auth requests to HTTP as fallback.
        # Request: {"params":{"hash":"...","hash2":"..."},"type":4}
        # Response: base64-encoded serial string
        # =====================================================================
        if body and isinstance(body, dict) and body.get("type") == 4 and method == "POST":
            log.info("    -> GetSerial (type 4 auth request via HTTP)")
            self._send_text(200, SPOOFED_SERIAL)
            return

        # =====================================================================
        # Catch-all: log unknown routes for discovery
        # =====================================================================
        log.info(f"    -> UNKNOWN ROUTE (logging for analysis)")
        self._send_express_404(method)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    def do_OPTIONS(self):
        self._route("OPTIONS")

    def do_HEAD(self):
        self._route("HEAD")


def main():
    # Create directories
    LUA_DIR.mkdir(exist_ok=True)
    # Create nl/ directories
    NL_DIR.mkdir(parents=True, exist_ok=True)
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    LANGS_DIR.mkdir(parents=True, exist_ok=True)

    server = HTTPServer((HOST, PORT), NLRequestHandler)
    log.info(f"Neverlose HTTP server on http://{HOST}:{PORT}/")
    log.info(f"  Serial: {SPOOFED_SERIAL[:40]}...")
    log.info("")
    log.info("Discovered HTTP routes (via MakeRequest, vtable slot 0):")
    log.info("  GET /api/config")
    log.info("  GET /api/getavatar?size=100&token=<TOKEN>")
    log.info("  GET /api/sendlog?token=T&a=0&build=B&cont=C&dump=D&cheat=csgo")
    log.info("  GET /lua/<name>?token=T&cheat=csgo&build=B")
    log.info("")
    log.info("Additional routes (scripts/configs/langs management):")
    log.info("  GET/POST /api/scripts       - List/create scripts")
    log.info("  GET/POST /api/scripts/<name> - Get/update specific script")
    log.info("  GET/POST /api/configs       - List/create configs")
    log.info("  GET/POST /api/configs/<name> - Get/update specific config")
    log.info("  GET/POST /api/langs         - List/create languages")
    log.info("  GET/POST /api/langs/<code>   - Get/update specific language")
    log.info("")
    log.info("Note: Most requests use WebSocket (fn3, vtable slot 3) via wss_server.py")
    log.info("  WebSocket JSON types: {\"type\":0..5, \"params\":{...}}")
    log.info("")
    log.info("Waiting for requests...")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("\nShutting down...")
        if REQUEST_LOG:
            log_path = Path(__file__).parent / "request_log.json"
            with open(log_path, "w") as f:
                json.dump(REQUEST_LOG, f, indent=2)
            log.info(f"Saved {len(REQUEST_LOG)} requests to {log_path}")
        server.server_close()


if __name__ == "__main__":
    main()
