#!/usr/bin/env python3
"""
Local demo server cho Lab 11 — gọi API THẬT để minh hoạ guardrails chặn thế nào.

    python scripts/demo_server.py          # rồi mở http://127.0.0.1:8011

Vì sao cần server này (không nhúng key vào HTML):
  - Key đọc từ ``.env`` ở PHÍA SERVER (OPENROUTER_API_KEY cho Blue,
    OPENAI_API_KEY cho Red / Red Advance). Key KHÔNG bao giờ nằm trong file
    HTML và KHÔNG bị commit.
  - Trang web gọi cùng origin (``/ask``) nên không vướng CORS.
  - Chỉ bind 127.0.0.1 (máy cục bộ), không mở ra ngoài.

Endpoint:
  GET  /            → demo/lab11_live.html
  GET  /health      → {ok, keys: {...}}
  POST /ask         → {target, message} → kết quả chặn / leak từ model thật

Mỗi request chạy tuần tự (1 khoá) vì Blue dùng bộ đếm plugin để suy ra lớp chặn,
và model Blue (OpenRouter free) trả lời chậm (~10–200 s/câu).
"""
from __future__ import annotations

import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from core.config import (  # noqa: E402
    blue_provider_label,
    get_openai_api_key,
    get_openrouter_api_key,
    get_red_provider,
    red_provider_label,
)

_LOCK = threading.Lock()
_STATE: dict = {}


def _blue():
    if "blue" not in _STATE:
        from assignment.pipeline import (
            BluePipeline,
            build_observability,
            build_production_plugins,
        )

        plugins = build_production_plugins(use_llm_judge=False)
        audit, monitor = build_observability()
        _STATE["blue"] = BluePipeline(plugins, audit, monitor)
    return _STATE["blue"]


def _red_default():
    if "red" not in _STATE:
        from agents.agent import create_red_agent_default

        _STATE["red"] = create_red_agent_default()
    return _STATE["red"]


def _red_advance():
    if "red_advance" not in _STATE:
        from agents.guards_agent import create_red_agent_advance

        _STATE["red_advance"] = create_red_agent_advance()
    return _STATE["red_advance"]


async def _ask(target: str, message: str) -> dict:
    from attacks.attacks import classify_attack_outcome, response_leaked_secrets
    from core.utils import chat_with_agent

    if target == "blue":
        row = await _blue().process(message, user_id="demo_user")
        return {
            "target": "Blue",
            "blocked": row["blocked"],
            "layer": row["layer"],
            "blocked_at": _describe_blue(row),
            "leaked": response_leaked_secrets(row["response_preview"]),
            "response": row["response_preview"],
            "latency_ms": row["latency_ms"],
            "details": row.get("details"),
        }

    name = "red_default" if target == "red" else "red_advance"
    agent, runner = _red_default() if target == "red" else _red_advance()
    import time

    t0 = time.perf_counter()
    response, _ = await chat_with_agent(agent, runner, message)
    latency = round((time.perf_counter() - t0) * 1000, 1)
    outcome = classify_attack_outcome(message, response, target_name=name)
    return {
        "target": "Red" if target == "red" else "Red Advance",
        "blocked": outcome["blocked"],
        "layer": outcome["layer"],
        "blocked_at": outcome["blocked_at"],
        "leaked": outcome["leaked"],
        "response": response,
        "latency_ms": latency,
    }


def _describe_blue(row: dict) -> str:
    layer = row["layer"]
    if not row["blocked"]:
        return "PASSED — câu hỏi hợp lệ, model Blue đã trả lời"
    reason = (row.get("details") or {}).get("reason")
    sig = (row.get("details") or {}).get("signals") or []
    issues = (row.get("details") or {}).get("issues") or []
    if layer == "rate_limiter":
        return "BLOCKED — rate limiter (quá nhiều request)"
    if layer == "input_guardrail":
        extra = ", ".join(sig) if sig else reason
        return f"BLOCKED_INPUT — input guardrail ({extra})"
    if layer == "output_guardrail":
        return f"BLOCKED_OUTPUT — output filter che ({', '.join(issues)})"
    return f"BLOCKED — {layer}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # bớt log ồn
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html", "/lab11_live.html"):
            page = _ROOT / "demo" / "lab11_live.html"
            if not page.is_file():
                return self._send(404, b"demo/lab11_live.html khong tim thay", "text/plain; charset=utf-8")
            return self._send(200, page.read_bytes(), "text/html; charset=utf-8")
        if self.path == "/health":
            red = get_red_provider()
            body = json.dumps({
                "ok": True,
                "blue_model": blue_provider_label(),
                "red_model": red_provider_label(),
                "keys": {
                    "openrouter": bool(get_openrouter_api_key()),
                    "openai": bool(get_openai_api_key()) if red == "openai" else None,
                },
            }).encode("utf-8")
            return self._send(200, body, "application/json; charset=utf-8")
        return self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if self.path != "/ask":
            return self._send(404, b"not found", "text/plain; charset=utf-8")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            target = (payload.get("target") or "blue").strip()
            message = payload.get("message") or ""
            if target not in {"blue", "red", "red_advance"}:
                raise ValueError("target phải là blue | red | red_advance")
        except Exception as exc:
            return self._send(400, json.dumps({"ok": False, "error": str(exc)}).encode(), "application/json; charset=utf-8")

        with _LOCK:  # tuần tự hoá: Blue suy ra lớp chặn bằng bộ đếm plugin
            try:
                result = asyncio.run(_ask(target, message))
                result["ok"] = True
            except Exception as exc:
                result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return self._send(200, json.dumps(result, ensure_ascii=False).encode("utf-8"),
                          "application/json; charset=utf-8")


def main():
    host, port = "127.0.0.1", 8011
    if not get_openrouter_api_key():
        print("CẢNH BÁO: thiếu OPENROUTER_API_KEY trong .env — Blue sẽ lỗi khi gọi.")
    if get_red_provider() == "openai" and not get_openai_api_key():
        print("CẢNH BÁO: thiếu OPENAI_API_KEY trong .env — Red / Red Advance sẽ lỗi khi gọi.")
    print(f"Blue  : {blue_provider_label()}")
    print(f"Red   : {red_provider_label()}")
    print(f"\nĐang chạy demo tại  http://{host}:{port}   (Ctrl+C để dừng)")
    print("Key đọc từ .env phía server — không nằm trong HTML, không bị commit.\n")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nĐã dừng demo server.")
