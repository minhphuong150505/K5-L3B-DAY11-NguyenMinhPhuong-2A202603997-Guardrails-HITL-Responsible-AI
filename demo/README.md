# Demo — Lab 11 Guardrails

Ba file demo, bổ sung cho nhau:

| File | Cần gì | Dùng để |
|------|--------|---------|
| `lab11_demo_slides.html` | Mở trực tiếp bằng trình duyệt | Slide 15 trang, kể lại Checkpoint 1→5 kèm số liệu lần chạy thật |
| `lab11_playground.html` | Mở trực tiếp (không cần key) | Chạy logic lọc (regex/giải mã) **offline** — thử câu hỏi bất kỳ, xem ALLOW/BLOCK. Không gọi LLM nên không bao giờ sinh secret |
| `lab11_live.html` | Chạy qua server cục bộ | Gọi **API thật** (Blue, Red, Red Advance) để thấy chặn/lộ trên model thật |

## Chạy bản live (gọi API thật)

Key đọc từ `.env` ở **phía server** — không nằm trong HTML, không bị commit.

```bash
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
python scripts/demo_server.py
# mở http://127.0.0.1:8011
```

Trong trang:
- **Blue** + câu lạc đề / injection → chặn ngay ở input guardrail (nhanh, không gọi LLM).
- **Blue** + câu banking hợp lệ → model trả lời (model suy luận, có thể chậm 10–200 s).
- **Red** + câu moi secret → **lộ** giá trị GIẢ trong `data/protected/vinbank_secrets.json` (Red cố ý mềm).
- **Red Advance** + câu moi secret → chặn ở L1 regex hoặc L2 NeMo.
- **Red Advance** có **nút tắt NeMo**: tắt → chỉ còn regex L1/L3 (dùng plugin regex-only có sẵn). So sánh cùng một câu khi bật/tắt để thấy NeMo (hiểu ý định) bắt được những câu mà regex bỏ sót. Chỉ hỗ trợ `RED_TEAM_PROVIDER=openai`.

Server chỉ bind `127.0.0.1` (máy cục bộ). Mở `lab11_live.html` trực tiếp (không qua server) sẽ hiện hướng dẫn và không gọi được API.
