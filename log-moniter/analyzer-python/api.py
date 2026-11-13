from datetime import datetime, timedelta
from collections import Counter
from pathlib import Path
import json

from fastapi import FastAPI

app = FastAPI(title="로그 분석 API")

LOG_FILE = Path(__file__).with_name("logs.json")
FAILURE_THRESHOLD = 10
WINDOW_MINUTES = 5


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/analyze")
def analyze():
    with LOG_FILE.open(encoding="utf-8") as file:
        logs = json.load(file)

    now = datetime.now()
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)

    recent_failures = [
        log for log in logs
        if cutoff <= datetime.fromisoformat(log["timestamp"]) <= now
        and log.get("event") == "login_failed"
    ]

    counts = Counter(log.get("ip", "unknown") for log in recent_failures)

    alerts = [
        {
            "ip": ip,
            "count": count,
            "message": f"최근 {WINDOW_MINUTES}분 로그인 실패 {count}회",
        }
        for ip, count in counts.items()
        if count >= FAILURE_THRESHOLD
    ]

    return {
        "total_logs": len(logs),
        "recent_login_failures": sum(counts.values()),
        "alerts": alerts,
    }