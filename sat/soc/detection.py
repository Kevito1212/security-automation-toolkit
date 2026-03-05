from __future__ import annotations

from uuid import uuid4
from pathlib import Path
import json
from collections import defaultdict
from datetime import datetime, timezone


def _iso_z(dt: datetime) -> str:
    """Retorna timestamp em UTC com sufixo Z (padrão SIEM-friendly)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (
        dt.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _base_alert(
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    src_ip: str,
    mitre: list[str],
) -> dict:
    """Schema base padronizado para alertas."""
    return {
        "alert_id": str(uuid4()),
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": severity,
        "status": "open",
        "entities": {"src_ip": src_ip},
        "mitre": mitre,
    }


def _parse_ts_utc(ts: str) -> datetime:
    """
    Converte timestamp ISO do ingest (ex: "2026-02-25T10:01:55") para datetime com tz UTC.
    (Assumimos UTC para as contas; para correlação isso é suficiente.)
    """
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _read_jsonl(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {path}")

    events: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def _write_jsonl(path: str | Path, rows: list[dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def detect_bruteforce_window(
    events_path: str,
    output_path: str,
    threshold: int = 5,
    window_seconds: int = 120,
) -> int:
    """
    Detecta brute force (somente falhas) usando sliding window.
    Gera 1 alerta por IP.
    """
    events_file = Path(events_path)
    output_file = Path(output_path)

    if not events_file.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {events_file}")

    # ip -> list[datetime]
    failed_times: dict[str, list[datetime]] = defaultdict(list)

    with events_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            event = json.loads(line)

            if event.get("event_type") != "ssh_login_failed":
                continue

            ip = event.get("src_ip")
            ts = event.get("timestamp")
            if not ip or not ts:
                continue

            dt = _parse_ts_utc(ts)
            failed_times[ip].append(dt)

    alerts: list[dict] = []

    for ip, times in failed_times.items():
        times.sort()
        i = 0

        for j in range(len(times)):
            while (times[j] - times[i]).total_seconds() > window_seconds:
                i += 1

            count = j - i + 1

            if count >= threshold:
                alert = _base_alert(
                    rule_id="SAT-SSH-001",
                    title="SSH Brute Force Detected",
                    description=f"Multiple SSH login failures from {ip} within {window_seconds}s.",
                    severity="high",
                    src_ip=ip,
                    mitre=["T1110"],
                )

                alert.update(
                    {
                        "timestamps": {
                            "first_seen": _iso_z(times[i]),
                            "last_seen": _iso_z(times[j]),
                        },
                        "evidence": {
                            "failed_attempts": count,
                            "threshold": threshold,
                            "window_seconds": window_seconds,
                        },
                        "priority": "P2",
                        "confidence": 0.7,
                        "alert_type": "brute_force_detected",
                    }
                )

                alerts.append(alert)
                break  # 1 alerta por IP

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")

    return len(alerts)


def detect_possible_compromise(
    input_jsonl: str | Path,
    output_jsonl: str | Path,
    threshold: int = 5,
    window_seconds: int = 120,
) -> int:
    """
    Regra (correlação):
    - Se um IP tiver >= threshold eventos ssh_login_failed dentro de window_seconds
    - E existir um ssh_login_success do mesmo IP logo após essas falhas (dentro da mesma janela),
      gerar alerta CRITICAL de possível comprometimento (Brute Force -> Valid Accounts).
    Gera 1 alerta por IP.
    """
    events = _read_jsonl(input_jsonl)

    # agrupa por IP e ordena
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        ip = e.get("src_ip")
        ts = e.get("timestamp")
        if not ip or not ts:
            continue
        by_ip[ip].append(e)

    # ordena por datetime (mais seguro do que por string)
    for ip in by_ip:
        by_ip[ip].sort(key=lambda x: _parse_ts_utc(x.get("timestamp", "1970-01-01T00:00:00")))

    alerts: list[dict] = []

    for ip, evs in by_ip.items():
        failed: list[tuple[datetime, str | None]] = []
        success: list[tuple[datetime, str | None]] = []

        for e in evs:
            et = e.get("event_type")
            ts = e.get("timestamp")
            if not ts:
                continue

            dt = _parse_ts_utc(ts)
            user = e.get("user")

            if et == "ssh_login_failed":
                failed.append((dt, user))
            elif et == "ssh_login_success":
                success.append((dt, user))

        if len(failed) < threshold or not success:
            continue

        i = 0
        for j in range(len(failed)):
            while (failed[j][0] - failed[i][0]).total_seconds() > window_seconds:
                i += 1

            window_size = j - i + 1

            if window_size >= threshold:
                first_seen = failed[i][0]
                last_failed = failed[j][0]
                cutoff_ts = last_failed.timestamp() + window_seconds

                found_success: tuple[datetime, str | None] | None = None
                for s_dt, s_user in success:
                    if s_dt >= last_failed and s_dt.timestamp() <= cutoff_ts:
                        found_success = (s_dt, s_user)
                        break

                if found_success:
                    s_dt, s_user = found_success

                    alert = _base_alert(
                        rule_id="SAT-SSH-002",
                        title="Possible Account Compromise",
                        description="Multiple SSH failures followed by a success within a short window (Brute Force -> Valid Accounts).",
                        severity="critical",
                        src_ip=ip,
                        mitre=["T1110", "T1078"],
                    )

                    alert["entities"]["user"] = s_user

                    alert.update(
                        {
                            "timestamps": {
                                "first_seen": _iso_z(first_seen),
                                "last_seen": _iso_z(s_dt),
                            },
                            "evidence": {
                                "failed_attempts": window_size,
                                "threshold": threshold,
                                "window_seconds": window_seconds,
                                "last_failed": _iso_z(last_failed),
                            },
                            "note": "Multiple failures followed by a success (possible compromise)",
                            "priority": "P1",
                            "confidence": 0.9,
                            "alert_type": "possible_account_compromise",
                        }
                    )

                    alerts.append(alert)
                    break  # 1 alerta por IP

    _write_jsonl(output_jsonl, alerts)
    return len(alerts)
