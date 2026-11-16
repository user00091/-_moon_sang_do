
#!/usr/bin/env python3
"""로그 이상 데이터 자동 정제기 (Flask 웹 서버 버전)"""
import json
import os
import random
import re
import sys
import time
from datetime import datetime

# 1. 플라스크 임포트 부분에 render_template_string을 정확히 포함시킵니다.
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

REQUIRED = ["ts", "level", "service", "msg"]
LEVELS = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}
MAXLEN = 2000

REASON = {
    "duplicate": "중복",
    "future_timestamp": "미래 시간",
    "missing_field": "필수 필드 누락",
    "parse_error": "JSON 파싱 실패",
    "bad_timestamp": "시간 형식 오류",
    "too_long": "초과 길이",
    "invalid_level": "알 수 없는 level",
}

PII = [
    (re.compile(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b", re.ASCII), "[CARD]"),
    (re.compile(r"\b\d{6}-[1-4]\d{6}\b", re.ASCII), "[RRN]"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+", re.ASCII), "[EMAIL]"),
    (re.compile(r"bearer\s+[a-z0-9._-]{10,}", re.ASCII | re.IGNORECASE), "Bearer [TOKEN]"),
]
TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?", re.ASCII)


def truthy(v):
    if v is None or v is False:
        return False
    if isinstance(v, str):
        return v != ""
    if isinstance(v, (int, float)):
        return v != 0
    return True


def parse_ts(s):
    if not isinstance(s, str):
        return None
    m = TS_RE.match(s)
    if not m:
        return None
    Y, M, D, h, mi = (int(m.group(i)) for i in range(1, 6))
    sec = int(m.group(6)) if m.group(6) else 0
    if sec > 59:
        return None
    try:
        return int(datetime(Y, M, D, h, mi, sec).timestamp())
    except (ValueError, OverflowError, OSError):
        return None


def clean_logs(lines):
    ok, quarantine, stats, masked = [], [], {}, 0
    seen = set()
    now = int(time.time()) + 5 * 60

    def rej(raw, why):
        stats[why] = stats.get(why, 0) + 1
        quarantine.append({"reason": why, "raw": raw})

    for raw in lines:
        if len(raw.encode("utf-8")) > MAXLEN:
            rej(raw, "too_long")
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            rec = None
        if not isinstance(rec, dict):
            rej(raw, "parse_error")
            continue
        if not all(truthy(rec.get(k)) for k in REQUIRED):
            rej(raw, "missing_field")
            continue
        ts = parse_ts(rec["ts"])
        if ts is None:
            rej(raw, "bad_timestamp")
            continue
        if ts > now:
            rej(raw, "future_timestamp")
            continue
        level = rec["level"]
        if not isinstance(level, str) or level not in LEVELS:
            rej(raw, "invalid_level")
            continue
        if raw in seen:
            rej(raw, "duplicate")
            continue
        seen.add(raw)

        msg = rec["msg"]
        if not isinstance(msg, str):
            msg = json.dumps(msg, ensure_ascii=False)
        hit = False
        for pat, rep in PII:
            new = pat.sub(rep, msg)
            if new != msg:
                hit = True
            msg = new
        if hit:
            masked += 1
        rec["msg"] = msg
        ok.append({"raw": raw, "rec": rec, "t": ts, "msg": msg, "level": level})
    return ok, quarantine, stats, masked


def med(a):
    if not a:
        return 0.0
    a = sorted(a)
    m = len(a) // 2
    return a[m] if len(a) % 2 else (a[m - 1] + a[m]) / 2


def robust_z(v):
    m = med(v)
    mad = med([abs(x - m) for x in v])
    if mad == 0:
        mad = 1e-9
    return m, [0.6745 * (x - m) / mad for x in v]


def volume(ok, th):
    if not ok:
        return [], 0.0
    buckets = {}
    for r in ok:
        b = buckets.setdefault(r["t"] // 60, [0, 0])
        b[0] += 1
        if r["level"] in ("ERROR", "FATAL"):
            b[1] += 1
    rows = []
    for k in range(min(buckets), max(buckets) + 1):
        tot, err = buckets.get(k, (0, 0))
        rows.append({"k": k, "t": tot, "e": err / tot if tot else 0.0, "why": []})
    med_t, zt = robust_z([r["t"] for r in rows])
    _, ze = robust_z([r["e"] for r in rows])
    for r, a, b in zip(rows, zt, ze):
        if abs(a) > th:
            r["why"].append("로그량 급증" if a > 0 else "로그량 급감")
        if b > th:
            r["why"].append("에러율 급증")
    return rows, med_t


# 2. make_sample 함수를 웹 라우트보다 위쪽에 배치합니다.
def make_sample():
    g = random.Random(42)
    start = (int(time.time()) - 130 * 60) // 60 * 60
    svc = ["auth", "payment", "gateway"]
    lvls = ["INFO"] * 8 + ["DEBUG", "WARN"]

    def J(ts, lv, sv, msg):
        return json.dumps({"ts": ts, "level": lv, "service": sv, "msg": msg}, ensure_ascii=False, separators=(",", ":"))

    L = []
    for m in range(120):
        n = g.randint(35, 45)
        er = 0.03
        if 80 <= m < 90:
            n, er = g.randint(150, 200), 0.45
        if 40 <= m < 43:
            n = g.randint(0, 3)
        for _ in range(n):
            ts = datetime.fromtimestamp(start + m * 60 + g.randint(0, 59)).strftime("%Y-%m-%dT%H:%M:%S")
            u = g.randint(1000, 9999)
            is_err = g.random() < er
            lv = "ERROR" if is_err else g.choice(lvls)
            if is_err:
                msg = f"DB connection timeout after {g.randint(1, 30)}s user={u}"
            else:
                msg = f"login ok user={u} ip=10.0.{g.randint(0, 9)}.{g.randint(1, 254)}"
            L.append(J(ts, lv, g.choice(svc), msg))
    return L


# 3. Flask 웹 라우트 설정
@app.route("/")
def index():
    return render_template_string("""
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>로그 이상 데이터 자동 정제기</title>
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f8; color: #1f2328; max-width: 900px; margin: 40px auto; padding: 20px; }
    h1 { color: #2563eb; font-size: 24px; margin-bottom: 5px; }
    p.subtitle { color: #57606a; margin-top: 0; margin-bottom: 20px; font-size: 14px; }
    .card { background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    textarea { width: 100%; height: 140px; font-family: monospace; font-size: 13px; padding: 10px; border: 1px solid #d0d7de; border-radius: 6px; box-sizing: border-box; resize: vertical; }
    .btn-group { margin-top: 12px; display: flex; gap: 10px; align-items: center; }
    button { background: #2563eb; color: #fff; border: 0; padding: 10px 18px; border-radius: 6px; font-weight: 600; cursor: pointer; }
    button:hover { background: #1d4ed8; }
    button.secondary { background: #4b5563; }
    input[type="number"] { padding: 8px; border: 1px solid #d0d7de; border-radius: 6px; width: 70px; text-align: center; }
    .metrics { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-top: 15px; }
    .metric-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; text-align: center; }
    .metric-box .label { font-size: 12px; color: #64748b; margin-bottom: 4px; }
    .metric-box .value { font-size: 18px; font-weight: bold; color: #0f172a; }
</style>
</head>
<body>

<h1>🧹 로그 이상 데이터 자동 정제기</h1>
<p class="subtitle">규칙 기반 정제 및 통계 기반 이상 구간 탐지 시스템</p>

<div class="card">
    <label for="logInput"><strong>로그 입력 (한 줄에 JSON 하나씩)</strong></label>
    <textarea id="logInput" placeholder='{"ts":"2026-11-09T10:00:00","level":"INFO","service":"auth","msg":"login ok"}'></textarea>
    
    <div class="btn-group">
        <button onclick="runCleaner(true)" class="secondary">샘플 데이터로 실행</button>
        <button onclick="runCleaner(false)">입력한 로그로 실행</button>
        <div style="margin-left: auto; display: flex; align-items: center; gap: 8px;">
            <label for="thInput" style="font-size: 13px; color: #4b5563;">임계값(Z):</label>
            <input id="thInput" type="number" value="3.5" step="0.5">
        </div>
    </div>
</div>

<div id="resultCard" class="card" style="display:none;">
    <h3>📊 실행 결과 요약</h3>
    <div class="metrics">
        <div class="metric-box"><div class="label">원본 로그</div><div id="mTotal" class="value">0</div></div>
        <div class="metric-box"><div class="label">정상 통과</div><div id="mOk" class="value" style="color: #16a34a;">0</div></div>
        <div class="metric-box"><div class="label">격리</div><div id="mQuarantine" class="value" style="color: #dc2626;">0</div></div>
        <div class="metric-box"><div class="label">마스킹</div><div id="mMasked" class="value" style="color: #2563eb;">0</div></div>
        <div class="metric-box"><div class="label">이상 구간</div><div id="mAnomalies" class="value" style="color: #d97706;">0</div></div>
    </div>
</div>

<script>
async function runCleaner(isSample) {
    let lines = [];
    if (!isSample) {
        let text = document.getElementById('logInput').value.trim();
        if (!text) { alert("로그 데이터를 입력해주세요."); return; }
        lines = text.split('\\n').map(s => s.trim()).filter(Boolean);
    }
    let th = parseFloat(document.getElementById('thInput').value) || 3.5;

    let res = await fetch('/run', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ is_sample: isSample, lines: lines, th: th })
    });
    let data = await res.json();
    
    document.getElementById('resultCard').style.display = 'block';
    document.getElementById('mTotal').innerText = data.total + "건";
    document.getElementById('mOk').innerText = data.ok_count + "건";
    document.getElementById('mQuarantine').innerText = data.quarantine_count + "건";
    document.getElementById('mMasked').innerText = data.masked_count + "건";
    document.getElementById('mAnomalies').innerText = data.anomalies + "개";
}
</script>
</body>
</html>
    """)

@app.route("/run", methods=["POST"])
def run_web():
    req = request.json
    if req.get("is_sample"):
        lines = make_sample()
    else:
        lines = req.get("lines", [])
    
    th = float(req.get("th", 3.5))
    ok, quarantine, stats, masked = clean_logs(lines)
    rows, med_t = volume(ok, th)
    anomalies = sum(1 for r in rows if r["why"])
    
    return jsonify({
        "total": len(lines),
        "ok_count": len(ok),
        "quarantine_count": len(quarantine),
        "masked_count": masked,
        "anomalies": anomalies
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
