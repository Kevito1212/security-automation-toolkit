from pathlib import Path
import json
from collections import defaultdict
from datetime import datetime


def _parse_iso(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def detect_bruteforce_window(
    events_path: str,
    output_path: str,
    threshold: int = 5,
    window_seconds: int = 120
):
    events_file = Path(events_path)
    output_file = Path(output_path)

    if not events_file.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {events_file}")

    # ip -> list[datetime]
    failed_times = defaultdict(list)

    with events_file.open("r", encoding="utf-8") as f:
        for line in f:
            event = json.loads(line)

            if event.get("event_type") != "ssh_login_failed":
                continue

            ip = event.get("src_ip")
            ts = event.get("timestamp")
            if not ip or not ts:
                continue

            dt = _parse_iso(ts)
            if dt:
                failed_times[ip].append(dt)

    alerts = []

    for ip, times in failed_times.items():
        times.sort()
        i = 0
        for j in range(len(times)):
            # mantém janela: times[j] - times[i] <= window_seconds
            while (times[j] - times[i]).total_seconds() > window_seconds:
                i += 1
            count = j - i + 1
            if count >= threshold:
                alerts.append({
                    "alert_type": "brute_force_detected",
                    "severity": "high",
                    "src_ip": ip,
                    "failed_attempts": count,
                    "window_seconds": window_seconds,
                    "first_seen": times[i].isoformat(),
                    "last_seen": times[j].isoformat(),
                    "status": "open"
                })
                break  # 1 alerta por IP (por enquanto)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")

    return len(alerts)