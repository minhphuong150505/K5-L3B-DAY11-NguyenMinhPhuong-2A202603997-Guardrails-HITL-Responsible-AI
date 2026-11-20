"""
Assignment 11 — Monitoring & Alerts starter (TODO).

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


def default_metrics_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "metrics.json")


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts."""

    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Counters — update these from your pipeline after each request
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    # Đếm chi tiết theo layer (input_guardrail / output_guardrail / rate_limiter …)
    blocked_by_layer: dict = field(default_factory=dict)
    latencies_ms: list = field(default_factory=list)

    def record(self, *, blocked: bool, layer: str | None, latency_ms: float | None = None):
        """Cập nhật bộ đếm sau mỗi request (pipeline gọi)."""
        self.total_requests += 1
        if blocked:
            self.blocked_requests += 1
            key = layer or "unknown"
            self.blocked_by_layer[key] = self.blocked_by_layer.get(key, 0) + 1
        if layer == "rate_limiter":
            self.rate_limit_hits += 1
        if latency_ms is not None:
            self.latencies_ms.append(latency_ms)

    def check_metrics(self) -> list[Alert]:
        """Compute rates, append Alert objects when thresholds exceeded."""
        self.alerts = []
        snap = self.snapshot()
        if self.total_requests and snap["block_rate"] > self.block_rate_threshold:
            self.alerts.append(Alert(
                metric="block_rate",
                value=round(snap["block_rate"], 3),
                threshold=self.block_rate_threshold,
                message=(
                    f"Block rate {snap['block_rate']:.0%} > {self.block_rate_threshold:.0%} "
                    "— possible attack campaign or over-blocking."
                ),
            ))
        if self.rate_limit_hits >= self.rate_limit_hit_threshold:
            self.alerts.append(Alert(
                metric="rate_limit_hits",
                value=self.rate_limit_hits,
                threshold=self.rate_limit_hit_threshold,
                message=(
                    f"{self.rate_limit_hits} rate-limit hits ≥ {self.rate_limit_hit_threshold} "
                    "— possible flooding / cost attack."
                ),
            ))
        if self.judge_checks and snap["judge_fail_rate"] > self.judge_fail_rate_threshold:
            self.alerts.append(Alert(
                metric="judge_fail_rate",
                value=round(snap["judge_fail_rate"], 3),
                threshold=self.judge_fail_rate_threshold,
                message="LLM judge fail rate above threshold.",
            ))
        return self.alerts

    def export_json(self, filepath: str | None = None):
        """Write metrics + alerts to JSON under repo-root ``outputs/`` by default."""
        self.check_metrics()
        path = Path(filepath or default_metrics_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.snapshot()
        data["blocked_by_layer"] = dict(self.blocked_by_layer)
        if self.latencies_ms:
            lat = sorted(self.latencies_ms)
            data["latency_ms"] = {
                "count": len(lat),
                "avg": round(sum(lat) / len(lat), 1),
                "p50": lat[len(lat) // 2],
                "p95": lat[min(len(lat) - 1, int(len(lat) * 0.95))],
                "max": lat[-1],
            }
        data["thresholds"] = {
            "block_rate": self.block_rate_threshold,
            "rate_limit_hits": self.rate_limit_hit_threshold,
            "judge_fail_rate": self.judge_fail_rate_threshold,
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)

    def snapshot(self) -> dict:
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                }
                for a in self.alerts
            ],
        }
