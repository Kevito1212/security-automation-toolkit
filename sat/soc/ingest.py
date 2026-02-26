import re
from datetime import datetime
from pathlib import Path
from sat.soc.models import SocEvent

# syslog prefix: "Feb 25 10:00:01"
RE_SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})")

FAILED_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>[\d.]+)")
ACCEPTED_RE = re.compile(r"Accepted password for (?P<user>\w+) from (?P<ip>[\d.]+)")
SUDO_RE = re.compile(r"sudo:\s+(?P<user>\w+)")


def _parse_syslog_ts(line: str, year: int) -> str:
    """
    Retorna timestamp ISO a partir do prefixo syslog.
    Se não conseguir, fallback para now().
    """
    m = RE_SYSLOG_TS.search(line)
    if not m:
        return datetime.now().isoformat()

    ts_part = f"{year} {m.group('mon')} {m.group('day')} {m.group('hms')}"
    try:
        dt = datetime.strptime(ts_part, "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except Exception:
        return datetime.now().isoformat()


def ingest_auth_log(input_path: str, output_path: str, year: int | None = None):
    input_file = Path(input_path)
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    lines = input_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    events: list[SocEvent] = []

    y = year or datetime.now().year

    for line in lines:
        line = line.strip()
        if not line:
            continue

        ts_iso = _parse_syslog_ts(line, y)

        m = FAILED_RE.search(line)
        if m:
            events.append(SocEvent(
                timestamp=ts_iso,
                source="auth.log",
                event_type="ssh_login_failed",
                severity="medium",
                user=m.group("user"),
                src_ip=m.group("ip"),
                message="SSH login failed",
                raw=line
            ))
            continue

        m = ACCEPTED_RE.search(line)
        if m:
            events.append(SocEvent(
                timestamp=ts_iso,
                source="auth.log",
                event_type="ssh_login_success",
                severity="low",
                user=m.group("user"),
                src_ip=m.group("ip"),
                message="SSH login successful",
                raw=line
            ))
            continue

        m = SUDO_RE.search(line)
        if m:
            events.append(SocEvent(
                timestamp=ts_iso,
                source="auth.log",
                event_type="sudo_execution",
                severity="medium",
                user=m.group("user"),
                message="Sudo command executed",
                raw=line
            ))
            continue

    with output_file.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(event.to_json() + "\n")

    return len(events)