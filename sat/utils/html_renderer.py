from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader, select_autoescape


def _load_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"JSON não encontrado: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _parse_dt(dt_str: str | None) -> str:
    """
    Converte ISO 8601 (ex: 2026-02-11T15:30:00+00:00) para horário BRT (-03:00)
    de forma compatível com Windows (sem depender de ZoneInfo/IANA).
    """
    if not dt_str:
        return ""
    try:
        from datetime import datetime, timezone, timedelta

        dt_str = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(dt_str)

        # Se não tiver tz, assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        brt = timezone(timedelta(hours=-3))
        dt_brt = dt.astimezone(brt)

        return dt_brt.strftime("%d/%m/%Y %H:%M:%S") + " (BRT)"
    except Exception:
        return dt_str


def _risk_class(score: int) -> tuple[str, str]:
    """Retorna (risk_level, risk_level_class)"""
    if score >= 70:
        return ("ALTO", "high")
    if score >= 40:
        return ("MÉDIO", "medium")
    return ("BAIXO", "low")


def _build_findings(data: dict) -> list[dict]:
    """
    Constrói a lista findings esperada pelo template:
    [{host, port, service, note}, ...]
    """
    findings: list[dict] = []

    host = (
        data.get("details", {})
        .get("port_scan", {})
        .get("host")
        or "N/A"
    )

    open_ports = (
        data.get("summary", {}).get("open_ports")
        or data.get("details", {}).get("port_scan", {}).get("open_ports")
        or []
    )

    normalized_ports: list[tuple[int, str]] = []
    for item in open_ports:
        if isinstance(item, int):
            normalized_ports.append((item, ""))
        elif isinstance(item, dict):
            p = item.get("port")
            s = item.get("service") or item.get("service_hint") or ""
            if isinstance(p, int):
                normalized_ports.append((p, s))

    for port, svc in normalized_ports:
        findings.append({
            "host": host,
            "port": port,
            "service": svc or "unknown",
            "note": "Porta aberta detectada",
        })

    la = data.get("details", {}).get("log_analysis", {}) or {}
    failed_attempts = la.get("failed_attempts")
    top_ip = la.get("top_suspicious_ip")
    top_ip_count = la.get("top_suspicious_ip_count")

    if isinstance(failed_attempts, int) and failed_attempts > 0:
        note = f"{failed_attempts} tentativas de login falhas"
        if top_ip:
            if isinstance(top_ip_count, int):
                note += f" (IP mais suspeito: {top_ip} — {top_ip_count}x)"
            else:
                note += f" (IP mais suspeito: {top_ip})"
        findings.append({
            "host": host,
            "port": "-",
            "service": "log_analysis",
            "note": note,
        })

    pc = data.get("details", {}).get("password_check", {}) or {}
    verdict = (pc.get("result", {}) or {}).get("verdict")
    score = (pc.get("result", {}) or {}).get("score")

    if verdict and str(verdict).lower() != "forte":
        findings.append({
            "host": host,
            "port": "-",
            "service": "password_check",
            "note": f"Senha classificada como '{verdict}' (score: {score})",
        })

    return findings


def _sev_class(sev: str | None) -> str:
    sev = (sev or "").lower()
    if sev in ("high", "critical"):
        return "high"
    if sev == "medium":
        return "medium"
    return "low"


def _read_jsonl(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def _pick_priority_ip(soc_alerts_raw: list[dict]) -> str | None:
    """
    Pega o IP "mais importante" para montar timeline:
    - prioriza critical > high > medium > low
    """
    if not soc_alerts_raw:
        return None

    def sev_rank(sev: str | None) -> int:
        s = (sev or "").lower()
        if s == "critical":
            return 3
        if s == "high":
            return 2
        if s == "medium":
            return 1
        return 0

    best = None
    best_rank = -1
    for a in soc_alerts_raw:
        r = sev_rank(a.get("severity"))
        if r > best_rank:
            best_rank = r
            best = a

    return best.get("src_ip") if best else None


def _build_attack_timeline(
    events_jsonl_path: str | Path,
    focus_ip: str | None,
) -> list[dict]:
    """
    Monta timeline simples:
    - filtra eventos por IP (focus_ip)
    - ordena por timestamp
    - formata timestamp para BRT via _parse_dt
    """
    if not focus_ip:
        return []

    events = _read_jsonl(events_jsonl_path)
    filtered = [e for e in events if e.get("src_ip") == focus_ip]
    filtered.sort(key=lambda e: e.get("timestamp", ""))

    timeline: list[dict] = []
    for e in filtered:
        timeline.append({
            "timestamp": _parse_dt(e.get("timestamp")) or (e.get("timestamp") or ""),
            "event_type": e.get("event_type", ""),
            "user": e.get("user"),
            "src_ip": e.get("src_ip"),
            "message": e.get("message") or e.get("raw") or "",
        })

    return timeline


def render_html_report(
    final_report_json: str | Path,
    template_path: str | Path,
    output_html: str | Path,
) -> Path:
    final_report_json = Path(final_report_json)
    template_path = Path(template_path)
    output_html = Path(output_html)

    raw = _load_json(final_report_json)

    generated_at = raw.get("generated_at")
    data_generated_at = _parse_dt(generated_at) or "N/A"
    report_rendered_at = datetime.now().strftime("%d/%m/%Y %H:%M:%S") + " (BRT)"

    target = (
        raw.get("target")
        or raw.get("details", {}).get("port_scan", {}).get("host")
        or "N/A"
    )

    findings = _build_findings(raw)

    open_ports_count = len(raw.get("summary", {}).get("open_ports") or [])
    failed_logins = raw.get("summary", {}).get("failed_logins") or 0
    password_strength = (raw.get("summary", {}).get("password_strength") or "").lower()

    soc_alerts_raw = raw.get("details", {}).get("soc_alerts") or []
    if not isinstance(soc_alerts_raw, list):
        soc_alerts_raw = []

    soc_alerts: list[dict] = []
    for a in soc_alerts_raw:
        soc_alerts.append({
            "alert_type": a.get("alert_type", "soc_alert"),
            "severity": a.get("severity", "unknown"),
            "severity_class": _sev_class(a.get("severity")),
            "src_ip": a.get("src_ip", "N/A"),
            "failed_attempts": a.get("failed_attempts"),
            "window_seconds": a.get("window_seconds"),
            "first_seen": _parse_dt(a.get("first_seen")),
            "last_seen": _parse_dt(a.get("last_seen")),
            "status": a.get("status", "open"),
            "mitre": a.get("mitre") or [],
        })

    soc_alerts_count = len(soc_alerts)
    soc_high_count = sum(
        1 for a in soc_alerts_raw
        if str(a.get("severity", "")).lower() in ("high", "critical")
    )

    risk_score = 0
    risk_score += min(open_ports_count * 20, 60)
    risk_score += 10 if isinstance(failed_logins, int) and failed_logins >= 3 else 0
    risk_score += 15 if password_strength and password_strength != "forte" else 0

    risk_score += min(soc_alerts_count * 20, 40)
    risk_score += 20 if soc_high_count > 0 else 0

    risk_score = max(0, min(100, int(risk_score)))
    risk_level, risk_level_class = _risk_class(risk_score)

    executive_summary = (
        f"Foram identificados {open_ports_count} serviços expostos, "
        f"{failed_logins} tentativas de login falhas, senha '{password_strength or 'N/A'}' "
        f"e {soc_alerts_count} alerta(s) SOC (high/critical: {soc_high_count})."
    )

    recommendation = (
        "Revisar serviços expostos (portas abertas), aplicar hardening, "
        "investigar tentativas de login falhas e reforçar controles de autenticação."
    )

    # Timeline (usa eventos do pipeline)
    events_path = Path("outputs") / "soc_events_auth.jsonl"
    focus_ip = _pick_priority_ip(soc_alerts_raw)
    attack_timeline = _build_attack_timeline(events_path, focus_ip)

    data = {
        "data_generated_at": data_generated_at,
        "report_rendered_at": report_rendered_at,
        "target": target,
        "executive_summary": executive_summary,
        "risk_level": risk_level,
        "risk_level_class": risk_level_class,
        "risk_score": risk_score,
        "recommendation": recommendation,
        "findings": findings,
        "soc_alerts": soc_alerts,

        # dashboard metrics
        "open_ports_count": open_ports_count,
        "failed_logins": failed_logins,
        "password_strength": (password_strength or "n/a"),
        "soc_alerts_count": soc_alerts_count,
        "soc_high_count": soc_high_count,

        # timeline
        "attack_timeline": attack_timeline,
        "focus_ip": focus_ip or "",
    }

    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_path.name)
    html = template.render(**data)

    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(html, encoding="utf-8")
    return output_html
