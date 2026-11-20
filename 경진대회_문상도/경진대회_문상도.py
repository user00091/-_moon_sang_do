#!/usr/bin/env python3
"""로그 이상 데이터 자동 정제기: 로그인 Flask 앱용 블루프린트"""

import csv
import io
import ipaddress
import json
import random
import re
import socket
import time
import uuid
from collections import Counter, OrderedDict
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from flask import Blueprint, Response, jsonify, request
from flask_login import login_required


cleaner = Blueprint("cleaner", __name__)

MAX_BYTES = 20 * 1024 * 1024
MAXLEN = 2000
MAX_RESULTS = 5
RESULTS = OrderedDict()

REQUIRED = ["ts", "level", "service", "msg"]
LEVELS = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}

REASON = {
    "duplicate": "중복",
    "future_timestamp": "미래 시간",
    "missing_field": "필수 필드 누락",
    "parse_error": "형식 인식 실패(시간 정보 없음/깨진 JSON)",
    "bad_timestamp": "시간 형식 오류",
    "too_long": "초과 길이",
    "invalid_level": "알 수 없는 level",
}

PII = [
    (re.compile(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b", re.ASCII), "[CARD]"),
    (re.compile(r"\b\d{6}-[1-4]\d{6}\b", re.ASCII), "[RRN]"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+", re.ASCII), "[EMAIL]"),
    (
        re.compile(r"bearer\s+[a-z0-9._-]{10,}", re.ASCII | re.IGNORECASE),
        "Bearer [TOKEN]",
    ),
]

TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?",
    re.ASCII,
)

LEVEL_MAP = {
    "TRACE": "DEBUG",
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "NOTICE": "INFO",
    "WARN": "WARN",
    "WARNING": "WARN",
    "ERROR": "ERROR",
    "ERR": "ERROR",
    "SEVERE": "ERROR",
    "CRIT": "FATAL",
    "CRITICAL": "FATAL",
    "FATAL": "FATAL",
}

_LEVEL_PATTERN = (
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|SEVERE|CRIT|CRITICAL|FATAL)\b"
)
LEVEL_UP_RE = re.compile(_LEVEL_PATTERN)
LEVEL_ANY_RE = re.compile(_LEVEL_PATTERN, re.IGNORECASE)

MONTHS = {
    month: index + 1
    for index, month in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun",
         "jul", "aug", "sep", "oct", "nov", "dec"]
    )
}

TS_ISO = re.compile(
    r"(\d{4})[-/.](\d{2})[-/.](\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?"
)
TS_APACHE = re.compile(
    r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})"
)
TS_SYSLOG = re.compile(
    r"\b([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b"
)
ACCESS_RE = re.compile(r'"\s+(\d{3})\s')
SYSLOG_RE = re.compile(
    r"^[A-Za-z]{3}\s+\d{1,2}\s+[\d:]{8}\s+\S+\s+([\w./-]+?)(?:\[\d+\])?:"
)

TS_COLS = (
    "ts", "time", "timestamp", "datetime", "date",
    "@timestamp", "created_at", "logged_at",
)
MSG_COLS = ("msg", "message", "log", "text", "body", "description")
LVL_COLS = ("level", "severity", "loglevel", "log_level", "lvl")
SVC_COLS = (
    "service", "app", "source", "logger", "component",
    "hostname", "host", "name",
)


def truthy(value):
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return value != ""
    if isinstance(value, (int, float)):
        return value != 0
    return True


def parse_ts(value):
    if not isinstance(value, str):
        return None

    match = TS_RE.match(value)
    if not match:
        return None

    year, month, day, hour, minute = (
        int(match.group(index)) for index in range(1, 6)
    )
    second = int(match.group(6)) if match.group(6) else 0

    if second > 59:
        return None

    try:
        return int(
            datetime(year, month, day, hour, minute, second).timestamp()
        )
    except (ValueError, OverflowError, OSError):
        return None


def clean_logs(lines):
    ok, quarantine, stats, masked = [], [], {}, 0
    seen = set()
    now = int(time.time()) + 5 * 60

    def reject(raw, reason, line_number):
        stats[reason] = stats.get(reason, 0) + 1
        quarantine.append({
            "reason": reason,
            "raw": raw,
            "line": line_number,
        })

    for line_number, raw in enumerate(lines, start=1):
        if len(raw.encode("utf-8", errors="replace")) > MAXLEN:
            reject(raw, "too_long", line_number)
            continue

        try:
            record = json.loads(raw)
        except (ValueError, TypeError):
            record = None

        if not isinstance(record, dict):
            reject(raw, "parse_error", line_number)
            continue

        if not all(truthy(record.get(key)) for key in REQUIRED):
            reject(raw, "missing_field", line_number)
            continue

        timestamp = parse_ts(record["ts"])
        if timestamp is None:
            reject(raw, "bad_timestamp", line_number)
            continue

        if timestamp > now:
            reject(raw, "future_timestamp", line_number)
            continue

        level = record["level"]
        if not isinstance(level, str) or level not in LEVELS:
            reject(raw, "invalid_level", line_number)
            continue

        if raw in seen:
            reject(raw, "duplicate", line_number)
            continue
        seen.add(raw)

        original_msg = record["msg"]
        message = original_msg
        if not isinstance(message, str):
            message = json.dumps(message, ensure_ascii=False)

        hit = False
        for pattern, replacement in PII:
            new_message = pattern.sub(replacement, message)
            if new_message != message:
                hit = True
            message = new_message

        if hit:
            masked += 1

        record["msg"] = message
        ok.append({
            "raw": raw,
            "rec": record,
            "original_msg": original_msg,
            "t": timestamp,
            "msg": message,
            "level": level,
            "masked": hit,
            "line": line_number,
        })

    return ok, quarantine, stats, masked


def median(values):
    if not values:
        return 0.0

    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def robust_z(values):
    center = median(values)
    mad = median([abs(value - center) for value in values])
    if mad == 0:
        mad = max(1e-9, 0.1 * abs(center)) if center else 1e-9
    return center, [0.6745 * (value - center) / mad for value in values]


def volume(ok, threshold):
    if not ok:
        return [], 0.0

    buckets = {}
    for record in ok:
        bucket = buckets.setdefault(record["t"] // 60, [0, 0])
        bucket[0] += 1
        if record["level"] in ("ERROR", "FATAL"):
            bucket[1] += 1

    rows = []
    for key in range(min(buckets), max(buckets) + 1):
        total, errors = buckets.get(key, (0, 0))
        rows.append({
            "k": key,
            "t": total,
            "e": errors / total if total else 0.0,
            "why": [],
        })

    median_total, z_total = robust_z([row["t"] for row in rows])
    _, z_error = robust_z([row["e"] for row in rows])

    for row, zt, ze in zip(rows, z_total, z_error):
        row["zt"] = round(zt, 2)
        row["ze"] = round(ze, 2)

        if abs(zt) > threshold:
            row["why"].append("로그량 급증" if zt > 0 else "로그량 급감")
        if ze > threshold:
            row["why"].append("에러율 급증")

    return rows, median_total


def make_sample():
    generator = random.Random(42)
    start = (int(time.time()) - 130 * 60) // 60 * 60
    services = ["auth", "payment", "gateway"]
    levels = ["INFO"] * 8 + ["DEBUG", "WARN"]

    def make_json(timestamp, level, service, message):
        return json.dumps(
            {
                "ts": timestamp,
                "level": level,
                "service": service,
                "msg": message,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    lines = []
    for minute in range(120):
        count = generator.randint(35, 45)
        error_rate = 0.03

        if 80 <= minute < 90:
            k = minute - 79
            count = 40 + k * 12 + generator.randint(-2, 2)
            error_rate = 0.03 + k * 0.04

        if 40 <= minute < 43:
            count = generator.randint(0, 3)

        for _ in range(count):
            timestamp = datetime.fromtimestamp(
                start + minute * 60 + generator.randint(0, 59)
            ).strftime("%Y-%m-%dT%H:%M:%S")
            user_id = generator.randint(1000, 9999)
            is_error = generator.random() < error_rate
            level = "ERROR" if is_error else generator.choice(levels)

            if is_error:
                message = (
                    f"DB connection timeout after "
                    f"{generator.randint(1, 30)}s user={user_id}"
                )
            else:
                message = (
                    f"login ok user={user_id} "
                    f"ip=10.0.{generator.randint(0, 9)}."
                    f"{generator.randint(1, 254)}"
                )

            lines.append(
                make_json(timestamp, level, generator.choice(services), message)
            )

    return lines


def time_label(bucket):
    return datetime.fromtimestamp(bucket * 60).strftime("%m-%d %H:%M")


def normalize_message(message):
    """같은 종류의 에러를 묶기 위해 숫자를 #으로 바꾼다."""
    message = re.sub(r"\d+", "#", message)
    message = re.sub(
        r"^[\[(]?#[-/.]#[-/.]#[T ]#:#(?::#)?(?:[.,]#)?[\])]?\s*",
        "",
        message,
    )
    return message[:120]


def find_ts(text):
    match = TS_ISO.search(text)
    if match:
        year, month, day, hour, minute, second = match.groups()
        return (
            f"{year}-{month}-{day}T{hour}:{minute}:"
            f"{second or '00'}"
        )

    match = TS_APACHE.search(text)
    if match:
        day, month_name, year, hour, minute, second = match.groups()
        month = MONTHS.get(month_name.lower())
        if month:
            return (
                f"{year}-{month:02d}-{day}T"
                f"{hour}:{minute}:{second}"
            )

    match = TS_SYSLOG.search(text)
    if match:
        month_name, day, hour, minute, second = match.groups()
        month = MONTHS.get(month_name.lower())
        if month:
            return (
                f"{datetime.now().year}-{month:02d}-{int(day):02d}T"
                f"{hour}:{minute}:{second}"
            )

    return None


def guess_level(text):
    match = LEVEL_UP_RE.search(text) or LEVEL_ANY_RE.search(text)
    return LEVEL_MAP[match.group(1).upper()] if match else None


def make_log_json(timestamp, level, service, message):
    return json.dumps(
        {
            "ts": timestamp,
            "level": level,
            "service": service,
            "msg": message,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def text_to_json(line):
    timestamp = find_ts(line)
    if timestamp is None:
        return line

    service = "app"
    access_match = ACCESS_RE.search(line)

    if access_match:
        service = "web"
        status_code = int(access_match.group(1))
        level = (
            "ERROR" if status_code >= 500
            else "WARN" if status_code >= 400
            else "INFO"
        )
    else:
        level = guess_level(line) or "INFO"

    syslog_match = SYSLOG_RE.match(line)
    if syslog_match:
        service = syslog_match.group(1)

    return make_log_json(timestamp, level, service, line)


def normalize_timestamp(value):
    value = (value or "").strip()

    if value.isdigit() and len(value) in (10, 13):
        try:
            seconds = int(value) / (1000 if len(value) == 13 else 1)
            return datetime.fromtimestamp(seconds).strftime(
                "%Y-%m-%dT%H:%M:%S"
            )
        except (ValueError, OverflowError, OSError):
            return value

    return find_ts(value) or value


def try_csv(text):
    first = next((line for line in text.splitlines() if line.strip()), "")
    if not first or first.lstrip().startswith(("{", "[")):
        return None

    for delimiter in (",", "\t", ";", "|"):
        if delimiter not in first:
            continue

        try:
            rows = csv.reader(io.StringIO(text), delimiter=delimiter)
            names = [header.strip().lower() for header in next(rows)]

            time_index = next(
                (names.index(column) for column in TS_COLS if column in names),
                None,
            )
            message_index = next(
                (names.index(column) for column in MSG_COLS if column in names),
                None,
            )

            if time_index is None or message_index is None:
                continue

            level_index = next(
                (names.index(column) for column in LVL_COLS if column in names),
                None,
            )
            service_index = next(
                (names.index(column) for column in SVC_COLS if column in names),
                None,
            )

            def cell(row, index):
                return (
                    row[index].strip()
                    if index is not None and index < len(row)
                    else ""
                )

            result = []
            for row in rows:
                if not row or not any(value.strip() for value in row):
                    continue

                message = cell(row, message_index)
                raw_level = cell(row, level_index)
                level = (
                    LEVEL_MAP.get(raw_level.upper(), raw_level.upper())
                    if raw_level
                    else (guess_level(message) or "INFO")
                )

                result.append(
                    make_log_json(
                        normalize_timestamp(cell(row, time_index)),
                        level,
                        cell(row, service_index) or "app",
                        message,
                    )
                )

            return result
        except (csv.Error, StopIteration):
            continue

    return None


def decode_lines(data):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = data.decode("cp949")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")

    stripped = text.lstrip()

    if stripped.startswith("["):
        try:
            array = json.loads(stripped)
            if isinstance(array, list):
                return [
                    json.dumps(item, ensure_ascii=False, separators=(",", ":"))
                    for item in array
                ]
        except ValueError:
            pass

    csv_lines = try_csv(text)
    if csv_lines is not None:
        return csv_lines

    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        result.append(line if line.startswith("{") else text_to_json(line))

    return result


def build_segments(ok, rows, top_n=3):
    errors_by_minute = {}

    for record in ok:
        if record["level"] in ("ERROR", "FATAL"):
            errors_by_minute.setdefault(
                record["t"] // 60, Counter()
            )[normalize_message(record["msg"])] += 1

    groups = []
    current = None

    for row in rows:
        if not row["why"]:
            current = None
            continue

        if current is not None and row["k"] == current[-1]["k"] + 1:
            current.append(row)
        else:
            current = [row]
            groups.append(current)

    segments = []
    for group in groups:
        reasons = []
        for row in group:
            for reason in row["why"]:
                if reason not in reasons:
                    reasons.append(reason)

        errors = Counter()
        for row in group:
            errors.update(errors_by_minute.get(row["k"], {}))

        segments.append({
            "start": time_label(group[0]["k"]),
            "end": time_label(group[-1]["k"]),
            "minutes": len(group),
            "total": sum(row["t"] for row in group),
            "peak": max(row["t"] for row in group),
            "peak_err": round(max(row["e"] for row in group) * 100, 1),
            "max_zt": max(abs(row["zt"]) for row in group),
            "max_ze": max(row["ze"] for row in group),
            "reasons": ", ".join(reasons),
            "top_errors": [
                {"msg": message, "count": count}
                for message, count in errors.most_common(top_n)
            ],
            "k0": group[0]["k"],
            "k1": group[-1]["k"],
        })

    return segments


def save_result(payload):
    token = uuid.uuid4().hex
    RESULTS[token] = payload

    while len(RESULTS) > MAX_RESULTS:
        RESULTS.popitem(last=False)

    return token


def csv_safe(value):
    value = "" if value is None else str(value)
    if value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def to_csv(header, rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    writer.writerows(rows)
    return "\ufeff" + buffer.getvalue()


def check_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("http:// 또는 https:// 로 시작하는 주소만 가능합니다.")

    try:
        addresses = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        raise ValueError("주소를 찾을 수 없습니다.")

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0].split("%")[0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise ValueError("내부 주소는 허용되지 않습니다.")


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, message, headers, new_url):
        return None


def fetch_url(url):
    check_url(url)
    req = Request(url, headers={"User-Agent": "log-cleaner/1.0"})

    try:
        with build_opener(NoRedirectHandler).open(req, timeout=10) as response:
            data = response.read(MAX_BYTES + 1)
    except Exception as error:
        raise ValueError(
            "주소에서 데이터를 가져오지 못했습니다: %s" % error
        )

    if len(data) > MAX_BYTES:
        raise ValueError("데이터가 너무 큽니다 (20MB 초과).")

    return decode_lines(data)


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>로그 이상 데이터 자동 정제기</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f8; color: #1f2328; max-width: 900px; margin: 40px auto; padding: 20px; }
h1 { color: #2563eb; font-size: 24px; margin-bottom: 5px; }
p.subtitle { color: #57606a; margin-top: 0; margin-bottom: 20px; font-size: 14px; }
.card { background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
.section-title { font-weight: 700; margin-bottom: 8px; }
.row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.section { margin-bottom: 18px; padding-bottom: 18px; border-bottom: 1px solid #eef0f2; }
.section:last-child { border-bottom: 0; margin-bottom: 0; padding-bottom: 0; }
textarea { width: 100%; height: 120px; font-family: monospace; font-size: 13px; padding: 10px; border: 1px solid #d0d7de; border-radius: 6px; box-sizing: border-box; resize: vertical; }
input[type="text"] { flex: 1; min-width: 240px; padding: 9px; border: 1px solid #d0d7de; border-radius: 6px; }
input[type="number"] { padding: 8px; border: 1px solid #d0d7de; border-radius: 6px; width: 70px; text-align: center; }
button { background: #2563eb; color: #fff; border: 0; padding: 10px 18px; border-radius: 6px; font-weight: 600; cursor: pointer; }
button:hover { background: #1d4ed8; }
button:disabled { background: #94a3b8; cursor: not-allowed; }
button.secondary { background: #4b5563; }
button.secondary:hover { background: #374151; }
.metrics { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-top: 15px; }
.metric-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; text-align: center; }
.metric-box .label { font-size: 12px; color: #64748b; margin-bottom: 4px; }
.metric-box .value { font-size: 18px; font-weight: bold; color: #0f172a; }
#status { margin-top: 10px; font-size: 14px; color: #57606a; min-height: 20px; }
#status.error { color: #dc2626; }
.hint { font-size: 12px; color: #64748b; margin-top: 6px; }
table.at { width: 100%; border-collapse: collapse; font-size: 13px; }
table.at th, table.at td { border-bottom: 1px solid #e2e8f0; padding: 6px 8px; text-align: right; white-space: nowrap; }
table.at th:first-child, table.at td:first-child, table.at th:last-child, table.at td:last-child { text-align: left; }
table.at th { background: #f8fafc; color: #475569; }
table.at td.wrap { white-space: normal; text-align: left; min-width: 260px; word-break: break-all; }
table.at td.wrap div { margin-bottom: 3px; }
.dl { display: inline-block; background: #fff; color: #2563eb; border: 1px solid #2563eb; padding: 7px 12px; border-radius: 6px; font-size: 13px; font-weight: 600; text-decoration: none; margin: 0 8px 8px 0; }
.dl:hover { background: #eff6ff; }
h4.sub { margin: 18px 0 8px; font-size: 15px; }
@media (max-width: 700px) {
    .metrics { grid-template-columns: repeat(2, 1fr); }
}
</style>
</head>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns"></script>
<body>

<h1>🧹 로그 이상 데이터 자동 정제기</h1>
<p class="subtitle">규칙 기반 정제 및 통계 기반 이상 구간 탐지 시스템</p>

<div class="card">
    <div class="section">
        <div class="section-title">1. 파일 업로드</div>
        <div class="row">
            <input type="file" id="fileInput" accept=".log,.txt,.json,.jsonl,.ndjson,.csv,.tsv">
            <button id="btnFile" onclick="runCleaner('file')">파일로 실행</button>
        </div>
        <div class="hint">JSON, CSV, 일반 텍스트 로그(앱 로그·Nginx·Apache·syslog) 지원 · 최대 20MB</div>
    </div>

    <div class="section">
        <div class="section-title">2. 사이트 주소(URL)</div>
        <div class="row">
            <input type="text" id="urlInput" placeholder="https://example.com/app.log">
            <button id="btnUrl" onclick="runCleaner('url')">주소로 실행</button>
        </div>
        <div class="hint">http/https 주소만 가능하며 내부망 주소는 차단됩니다.</div>
    </div>

    <div class="section">
        <div class="section-title">3. 직접 붙여넣기 (JSON 또는 일반 텍스트)</div>
        <textarea id="logInput" placeholder='{"ts":"2026-11-09T10:00:00","level":"INFO","service":"auth","msg":"login ok"}'></textarea>
        <div class="row" style="margin-top:10px;">
            <button id="btnText" onclick="runCleaner('text')">입력한 로그로 실행</button>
            <button id="btnSample" onclick="runCleaner('sample')" class="secondary">샘플 데이터로 실행</button>
        </div>
    </div>

    <div class="row" style="justify-content:flex-end;">
        <label for="thInput" style="font-size:13px;color:#4b5563;">임계값(Z):</label>
        <input id="thInput" type="number" value="3.5" step="0.5">
    </div>
    <div id="status"></div>
</div>

<div id="resultCard" class="card" style="display:none;">
    <h3 style="margin-top:0;">📊 실행 결과 요약</h3>
    <div class="metrics">
        <div class="metric-box"><div class="label">원본 로그</div><div id="mTotal" class="value">0</div></div>
        <div class="metric-box"><div class="label">정상 통과</div><div id="mOk" class="value">0</div></div>
        <div class="metric-box"><div class="label">격리</div><div id="mQuarantine" class="value">0</div></div>
        <div class="metric-box"><div class="label">마스킹</div><div id="mMasked" class="value">0</div></div>
        <div class="metric-box"><div class="label">이상 구간</div><div id="mAnomalies" class="value">0</div></div>
    </div>
    <div id="detail" class="hint" style="margin-top:14px;font-size:13px;"></div>
    <div class="card" style="margin-top:16px;">
    <h4 class="sub">시간대별 로그량 및 에러율</h4>
    <canvas id="logChart"></canvas>
    </div>
    <div id="downloads" style="margin-top:16px;"></div>
    <h4 class="sub">격리 로그 상세</h4>
    <div id="quarantineWrap" style="overflow-x:auto;"></div>
    <h4 class="sub">마스킹 전·후 비교</h4>
    <div id="maskedWrap" style="overflow-x:auto;"></div>
    <h4 class="sub" id="segTitle" style="display:none;">🚨 이상 구간 (연속된 구간은 하나로 묶음)</h4>
    <div id="segWrap" style="overflow-x:auto;"></div>
    <details id="minWrap" style="margin-top:14px;display:none;">
        <summary style="cursor:pointer;font-size:13px;color:#475569;">분 단위 상세 보기</summary>
        <div id="anomalyWrap" style="overflow-x:auto;margin-top:8px;"></div>
    </details>
    
</div>

<script>
const runUrl = "/run";

function setStatus(message, isError) {
    const element = document.getElementById('status');
    element.textContent = message || '';
    element.className = isError ? 'error' : '';
}

function setBusy(busy) {
    ['btnFile', 'btnUrl', 'btnText', 'btnSample'].forEach(id => {
        document.getElementById(id).disabled = busy;
    });
}

function makeTable(headings) {
    const table = document.createElement('table');
    table.className = 'at';
    const header = table.insertRow();

    headings.forEach(text => {
        const th = document.createElement('th');
        th.textContent = text;
        header.appendChild(th);
    });
    return table;
}

function renderDetail(data) {
    const parts = [
        '임계값 ' + data.th,
        '분석한 1분 구간 ' + data.bucket_count + '개',
        '가장 큰 Z값 ' + data.max_z
    ];

    const stats = data.stats || {};
    const statKeys = Object.keys(stats);
    if (statKeys.length) {
        parts.push('격리 사유: ' + statKeys.map(key => key + ' ' + stats[key] + '건').join(', '));
    }
    document.getElementById('detail').textContent = parts.join('  |  ');

    const quarantineWrap = document.getElementById('quarantineWrap');
    quarantineWrap.textContent = '';

    const quarantineDetails = data.quarantine_details || [];
    if (quarantineDetails.length) {
        const quarantineTable = makeTable(['입력 줄', '격리 사유', '원문']);

        quarantineDetails.forEach(item => {
            const row = quarantineTable.insertRow();
            [item.line, item.reason, item.raw].forEach(value => {
                row.insertCell().textContent = value;
            });
        });

        quarantineWrap.appendChild(quarantineTable);
    } else {
        quarantineWrap.textContent = '격리된 로그가 없습니다.';
    }

    // 마스킹 전·후 비교 표시
    const maskedWrap = document.getElementById('maskedWrap');
    maskedWrap.textContent = '';

    const maskedDetails = data.masked_details || [];
    if (maskedDetails.length) {
        const maskedTable = makeTable(['입력 줄', '마스킹 전', '마스킹 후']);

        maskedDetails.forEach(item => {
            const row = maskedTable.insertRow();
            [item.line, item.before, item.after].forEach(value => {
                row.insertCell().textContent = value;
            });
        });

        maskedWrap.appendChild(maskedTable);
    } else {
        maskedWrap.textContent = '마스킹된 로그가 없습니다.';
    }

    const downloads = document.getElementById('downloads');
    downloads.textContent = '';

    const counts = data.counts || {};
    const definitions = [
        ['clean', '정상 로그 (.jsonl)'],
        ['quarantine', '격리 로그 (.csv)'],
        ['segments', '이상 구간 요약 (.csv)'],
        ['anomaly_logs', '이상 구간 로그 (.jsonl)']
    ];

    definitions.forEach(([kind, label]) => {
        const link = document.createElement('a');
        link.className = 'dl';
        link.href = data.download_base + '/' + kind;
        link.textContent = '⬇ ' + label + ' · ' + (counts[kind] || 0) + '건';
        downloads.appendChild(link);
    });

    const segmentWrap = document.getElementById('segWrap');
    const segmentTitle = document.getElementById('segTitle');
    segmentWrap.textContent = '';
    segmentTitle.style.display = 'block';

    const segments = data.segments || [];
    if (!segments.length) {
        segmentWrap.textContent = '탐지된 이상 구간이 없습니다.';
    } else {
        const table = makeTable([
            '구간', '지속', '총 로그', '최대 로그/분', '최대 에러율(%)',
            '최대 건수 Z', '최대 에러율 Z', '사유', '주요 에러 메시지'
        ]);

        segments.forEach(segment => {
            const row = table.insertRow();
            const range = segment.minutes > 1
                ? segment.start + ' ~ ' + segment.end
                : segment.start;

            [
                range, segment.minutes + '분', segment.total, segment.peak,
                segment.peak_err, segment.max_zt, segment.max_ze, segment.reasons
            ].forEach(value => {
                row.insertCell().textContent = value;
            });

            const errorCell = row.insertCell();
            errorCell.className = 'wrap';

            if (!segment.top_errors.length) {
                errorCell.textContent = '(에러 로그 없음)';
            } else {
                segment.top_errors.forEach(error => {
                    const line = document.createElement('div');
                    line.textContent = error.count + '건  ' + error.msg;
                    errorCell.appendChild(line);
                });
            }
        });

        segmentWrap.appendChild(table);
    }

    const anomalyWrap = document.getElementById('anomalyWrap');
    const minuteWrap = document.getElementById('minWrap');
    anomalyWrap.textContent = '';

    const anomalyRows = data.anomaly_rows || [];
    minuteWrap.style.display = anomalyRows.length ? 'block' : 'none';

    if (anomalyRows.length) {
        const table = makeTable([
            '시각', '로그 수', '에러율(%)', '건수 Z', '에러율 Z', '사유'
        ]);

        anomalyRows.forEach(rowData => {
            const row = table.insertRow();
            [
                rowData.time, rowData.count, rowData.err,
                rowData.zt, rowData.ze, rowData.why
            ].forEach(value => {
                row.insertCell().textContent = value;
            });
        });

        anomalyWrap.appendChild(table);
    }
}
let logChart = null;

function renderChart(rows) {
    const canvas = document.getElementById('logChart');
    if (!canvas) return;

    if (logChart) {
        logChart.destroy();
    }

    const labels = rows.map(row =>
        new Date(row.time).toLocaleTimeString('ko-KR', {
            hour: '2-digit',
            minute: '2-digit'
        })
    );
    const anomalies = rows.map(row => row.is_anomaly ? row.count : null);

    logChart = new Chart(canvas, {
        data: {
            labels: labels,
            datasets: [
                {
                    type: 'bar',
                    label: '분당 로그 건수',
                    data: rows.map(row => row.count),
                    yAxisID: 'y',
                    backgroundColor: 'rgba(37, 99, 235, 0.35)',
                    borderColor: '#2563eb',
                    borderWidth: 1
                },
                {
                    type: 'line',
                    label: '에러율 (%)',
                    data: rows.map(row => row.error_rate),
                    yAxisID: 'y1',
                    borderColor: '#dc2626',
                    backgroundColor: '#dc2626',
                    pointRadius: 2,
                    tension: 0.2
                },
                {
                    type: 'line',
                    label: '이상 구간',
                    data: anomalies,
                    yAxisID: 'y',
                    borderColor: '#d97706',
                    backgroundColor: '#d97706',
                    pointRadius: 5,
                    showLine: false
                }
            ]
        },
        options: {
            responsive: true,
            interaction: {
                mode: 'index',
                intersect: false
            },
            scales: {
                x: {
                    title: { display: true, text: '시각' }
                },
                y: {
                    beginAtZero: true,
                    title: { display: true, text: '로그 건수' }
                },
                y1: {
                    beginAtZero: true,
                    position: 'right',
                    title: { display: true, text: '에러율 (%)' },
                    grid: { drawOnChartArea: false }
                }
            }
        }
    });
}
async function runCleaner(mode) {
    const formData = new FormData();
    formData.append('mode', mode);

    let threshold = parseFloat(document.getElementById('thInput').value);
    if (Number.isNaN(threshold)) threshold = 3.5;
    formData.append('th', String(threshold));

    if (mode === 'file') {
        const file = document.getElementById('fileInput').files[0];
        if (!file) {
            setStatus('파일을 선택해주세요.', true);
            return;
        }
        formData.append('file', file);
    } else if (mode === 'url') {
        const url = document.getElementById('urlInput').value.trim();
        if (!url) {
            setStatus('주소를 입력해주세요.', true);
            return;
        }
        formData.append('url', url);
    } else if (mode === 'text') {
        const text = document.getElementById('logInput').value.trim();
        if (!text) {
            setStatus('로그 데이터를 입력해주세요.', true);
            return;
        }
        formData.append('text', text);
    }

    setBusy(true);
    setStatus('처리 중입니다...', false);

    try {
        const response = await fetch(runUrl, {method: 'POST', body: formData});
        const data = await response.json();

        if (!response.ok || data.error) {
            setStatus(data.error || ('서버 오류 (' + response.status + ')'), true);
            return;
        }

        document.getElementById('resultCard').style.display = 'block';
        document.getElementById('mTotal').textContent = data.total + '건';
        document.getElementById('mOk').textContent = data.ok_count + '건';
        document.getElementById('mQuarantine').textContent = data.quarantine_count + '건';
        document.getElementById('mMasked').textContent = data.masked_count + '건';
        document.getElementById('mAnomalies').textContent = data.anomalies + '개';

        renderDetail(data);
        renderChart(data.chart_rows || []);
        setStatus('완료되었습니다.', false);
    } catch (error) {
        setStatus('서버에 연결하지 못했습니다: ' + error, true);
    } finally {
        setBusy(false);
    }
}
</script>
</body>
</html>"""


def csv_safe(value):
    value = "" if value is None else str(value)
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def to_csv(header, rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    writer.writerows(rows)
    return "\ufeff" + buffer.getvalue()


def save_result(payload):
    token = uuid.uuid4().hex
    RESULTS[token] = payload

    while len(RESULTS) > MAX_RESULTS:
        RESULTS.popitem(last=False)

    return token


def process_input():
    if request.content_length and request.content_length > MAX_BYTES:
        return None, (jsonify({"error": "파일이나 요청 데이터가 너무 큽니다 (20MB 초과)."}), 413)

    mode = request.form.get("mode", "sample")
    try:
        threshold = float(request.form.get("th", 3.5))
    except (TypeError, ValueError):
        return None, (jsonify({"error": "임계값은 숫자여야 합니다."}), 400)

    try:
        if mode == "sample":
            lines = make_sample()
        elif mode == "file":
            file = request.files.get("file")
            if file is None:
                return None, (jsonify({"error": "파일을 선택해주세요."}), 400)
            data = file.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                return None, (jsonify({"error": "파일이 너무 큽니다 (20MB 초과)."}), 413)
            lines = decode_lines(data)
        elif mode == "url":
            url = request.form.get("url", "").strip()
            if not url:
                return None, (jsonify({"error": "주소를 입력해주세요."}), 400)
            lines = fetch_url(url)
        elif mode == "text":
            text = request.form.get("text", "")
            if not text.strip():
                return None, (jsonify({"error": "로그 데이터를 입력해주세요."}), 400)
            data = text.encode("utf-8")
            if len(data) > MAX_BYTES:
                return None, (jsonify({"error": "입력 내용이 너무 큽니다 (20MB 초과)."}), 413)
            lines = decode_lines(data)
        else:
            return None, (jsonify({"error": "알 수 없는 입력 방식입니다."}), 400)
    except ValueError as error:
        return None, (jsonify({"error": str(error)}), 400)

    if not lines:
        return None, (jsonify({"error": "처리할 로그가 없습니다."}), 400)

    return (lines, threshold), None


@cleaner.route("/cleaner")
@login_required
def index():
    return INDEX_HTML


@cleaner.route("/run", methods=["POST"])
@login_required
def run_web():
    processed, error_response = process_input()
    if error_response:
        return error_response

    lines, threshold = processed
    ok, quarantine, stats, masked = clean_logs(lines)
    rows, _median_total = volume(ok, threshold)

    anomaly_rows = [
        {
            "time": time_label(row["k"]),
            "count": row["t"],
            "err": round(row["e"] * 100, 1),
            "zt": row["zt"],
            "ze": row["ze"],
            "why": ", ".join(row["why"]),
        }
        for row in rows if row["why"]
    ]

    max_z = max(
        (max(abs(row["zt"]), row["ze"]) for row in rows),
        default=0.0,
    )
    segments = build_segments(ok, rows)

    anomaly_minutes = {row["k"] for row in rows if row["why"]}
    anomaly_logs = [
        record for record in ok
        if record["t"] // 60 in anomaly_minutes
    ]

    token = save_result({
        "ok": ok,
        "quarantine": quarantine,
        "segments": segments,
        "anomaly_logs": anomaly_logs,
    })

    return jsonify({
        "total": len(lines),
        "ok_count": len(ok),
        "quarantine_count": len(quarantine),
        "masked_count": masked,
        "anomalies": len(anomaly_rows),
        "anomaly_rows": anomaly_rows[:200],
        "chart_rows": [
            {
                "time": row["k"] * 60 * 1000,
                "count": row["t"],
                "error_rate": round(row["e"] * 100, 2),
                "is_anomaly": bool(row["why"]),
            }
            for row in rows
        ],
        "segments": [
            {key: value for key, value in segment.items() if key not in ("k0", "k1")}
            for segment in segments[:100]
        ],
        "bucket_count": len(rows),
        "max_z": round(max_z, 2),
        "th": threshold,
        "stats": {REASON.get(key, key): value for key, value in stats.items()},
        "quarantine_details": [
            {
                "line": item["line"],
                "reason": REASON.get(item["reason"], item["reason"]),
                "raw": item["raw"],
            }
            for item in quarantine[:200]
        ],
        "masked_details": [
            {
                "line": item["line"],
                "before": str(item["original_msg"]),
                "after": item["msg"],
            }
            for item in ok if item["masked"]
        ][:200],
        "counts": {
            "clean": len(ok),
            "quarantine": len(quarantine),
            "segments": len(segments),
            "anomaly_logs": len(anomaly_logs),
        },
        "download_base": f"/download/{token}",
    })


@cleaner.route("/download/<token>/<kind>")
@login_required
def download(token, kind):
    result = RESULTS.get(token)
    if result is None:
        return "결과가 만료되었습니다. 다시 실행해 주세요.", 404

    if kind == "clean":
        body = "".join(
            json.dumps(record["rec"], ensure_ascii=False) + "\n"
            for record in result["ok"]
        )
        filename = "clean_logs.jsonl"
        content_type = "application/x-ndjson; charset=utf-8"

    elif kind == "anomaly_logs":
        body = "".join(
            json.dumps(record["rec"], ensure_ascii=False) + "\n"
            for record in result["anomaly_logs"]
        )
        filename = "anomaly_logs.jsonl"
        content_type = "application/x-ndjson; charset=utf-8"

    elif kind == "quarantine":
        body = to_csv(
            ["사유", "원문"],
            [
                [REASON.get(item["reason"], item["reason"]), csv_safe(item["raw"])]
                for item in result["quarantine"]
            ],
        )
        filename = "quarantined_logs.csv"
        content_type = "text/csv; charset=utf-8"

    elif kind == "segments":
        body = to_csv(
            [
                "시작", "끝", "지속(분)", "총 로그", "최대 로그/분",
                "최대 에러율(%)", "최대 건수 Z", "최대 에러율 Z",
                "사유", "주요 에러 메시지",
            ],
            [
                [
                    segment["start"],
                    segment["end"],
                    segment["minutes"],
                    segment["total"],
                    segment["peak"],
                    segment["peak_err"],
                    segment["max_zt"],
                    segment["max_ze"],
                    csv_safe(segment["reasons"]),
                    csv_safe(
                        " | ".join(
                            f'{error["count"]}건 {error["msg"]}'
                            for error in segment["top_errors"]
                        )
                    ),
                ]
                for segment in result["segments"]
            ],
        )
        filename = "anomaly_segments.csv"
        content_type = "text/csv; charset=utf-8"

    else:
        return "알 수 없는 항목입니다.", 404

    return Response(
        body.encode("utf-8"),
        content_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )