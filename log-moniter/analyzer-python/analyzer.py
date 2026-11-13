import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

LOG_FILE = Path(__file__).with_name("logs.json")
FAILURE_THRESHOLD = 10
WINDOW_MINUTES = 5


def load_logs():
    with LOG_FILE.open(encoding="utf-8") as file:
        logs = json.load(file)

    for log in logs:
        log["timestamp"] = datetime.fromisoformat(log["timestamp"])

    return logs


def find_alerts(logs):
    now = datetime.now()
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)

    recent_failures = [
        log for log in logs
        if cutoff <= log["timestamp"] <= now
        and log.get("event") == "login_failed"
    ]

    counts = Counter(
        log.get("ip", "unknown")
        for log in recent_failures
    )

    return [
        {"ip": ip, "count": count}
        for ip, count in counts.items()
        if count >= FAILURE_THRESHOLD
    ]


if __name__ == "__main__":
    print("로그 분석을 시작합니다.")

    try:
        logs = load_logs()
        print(f"전체 로그: {len(logs)}건")

        alerts = find_alerts(logs)

        if alerts:
            for alert in alerts:
                print(
                    f"경고: {alert['ip']}에서 최근 "
                    f"{WINDOW_MINUTES}분간 로그인 실패 "
                    f"{alert['count']}회"
                )
        else:
            print("탐지된 이상 징후가 없습니다.")

    except FileNotFoundError:
        print(f"오류: {LOG_FILE.name} 파일을 찾을 수 없습니다.")
    except json.JSONDecodeError as error:
        print(f"오류: logs.json의 JSON 형식이 잘못됐습니다: {error}")
    except (KeyError, ValueError) as error:
        print(f"오류: 로그 데이터 형식을 확인해 주세요: {error}")