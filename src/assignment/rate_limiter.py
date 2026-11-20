"""
Assignment 11 — Rate Limiter starter (TODO).

Sliding-window, per-user rate limiting. Blocks abuse that other
guardrail layers do not address (flooding / cost attacks).
"""
from __future__ import annotations

from collections import defaultdict, deque
import contextvars
import time

from google.adk.plugins import base_plugin
from google.genai import types


# OpenAIRunner luôn truyền context user_id="student"; pipeline đặt user thật vào
# contextvar này trước mỗi request để rate limit đúng theo từng user.
CURRENT_USER: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "rate_limit_current_user", default=None
)


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0
        self.last_blocked = False

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Return Content to block, or None to allow."""
        self.total_count += 1
        user_id = (
            CURRENT_USER.get()
            or getattr(invocation_context, "user_id", None)
            or "anonymous"
        )
        now = time.time()
        window = self.user_windows[user_id]

        # 1. Trượt cửa sổ: bỏ timestamp cũ hơn window_seconds
        while window and window[0] <= now - self.window_seconds:
            window.popleft()

        # 2. Đã đủ quota → chặn, KHÔNG gọi LLM
        if len(window) >= self.max_requests:
            wait = self.window_seconds - (now - window[0])
            self.blocked_count += 1
            self.last_blocked = True
            return self._block_response(
                f"Rate limit exceeded ({self.max_requests} requests / "
                f"{self.window_seconds}s). Try again in {wait:.0f}s."
            )

        # 3. Còn quota → ghi nhận, cho qua
        window.append(now)
        self.last_blocked = False
        return None

    def reset(self, user_id: str | None = None):
        if user_id is None:
            self.user_windows.clear()
        else:
            self.user_windows.pop(user_id, None)
