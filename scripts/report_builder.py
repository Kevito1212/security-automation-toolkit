import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sat.utils.config_loader import load_config
from sat.utils.logger import get_logger

log = get_logger("report_builder")


def load_json(path: Path) -> dict | None:
    if not path.exists():
        log.warning(f"Arquivo não encontrado (pulando): {path}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.error(f"JSON inválido (pulando): {path}")
        return None


def load_jsonl(path: Path) -> list[dict]:
    """Lê JSONL e retorna lista de dicts. Se não existir, retorna lista vazia."""
    if not path.exists():
        log.warning(f"Arquivo não encontrado (pulando): {path}")
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            log.warning(f"Linha JSONL inválida (pulando): {path}")
    return rows


def normalize_alert(a: dict) -> dict:
    """
    Normaliza campos do alerta pro template HTML (flat fields):
    - src_ip
    - failed_attempts
    - window_seconds
    - first_seen / last_seen
    Também mantém o alerta original (não perde nada).
    """
    entities = a.get("entities") or {}
    evidence = a.get("evidence") or {}
    timestamps = a.get("timestamps") or {}

    # alguns alertas podem ter esses campos já no topo
    src_ip = a.get("src_ip") or entities.get("src_ip")
    failed_attempts = a.get("failed_attempts")
    if failed_attempts is None:
        failed_attempts = evidence.get("failed_attempts")

    window_seconds = a.get("window_seconds")
    if window_seconds is None:
        window_seconds = evidence.get("window_seconds")

    first_seen = a.get("first_seen") or timestamps.get("first_seen")
    last_seen = a.get("last_seen") or timestamps.get("last_seen")

    return {
        **a,
        "src_ip": src_ip,
        "failed_attempts": failed_attempts,
        "window_seconds": window_seconds,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def build_attack_timeline(events: list[dict], soc_alerts: list[dict]) -> list[dict]:
    """
    Gera timeline (lista ordenada) filtrando eventos cujo src_ip aparece nos alertas.
    Espera eventos com:
      - timestamp, event_type, src_ip, user, raw
    """
    ips = set()
    for a in soc_alerts:
        ip = a.get("src_ip") or (a.get("entities") or {}).get("src_ip")
        if ip and ip != "N/A":
            ips.add(ip)

    if not ips or not events:
        return []

    timeline: list[dict] = []
    for e in events:
        ip = e.get("src_ip")
        et = e.get("event_type")
        ts = e.get("timestamp")
        if not ip or not et or not ts:
            continue

        if ip in ips and et in ("ssh_login_failed", "ssh_login_success"):
            timeline.append(
                {
                    "timestamp": ts,
                    "event_type": et,
                    "user": e.get("user"),
                    "src_ip": ip,
                    "message": e.get("raw") or e.get("message"),
                }
            )

    # timestamps estão em ISO -> ordenar por string funciona OK aqui
    timeline.sort(key=lambda x: x["timestamp"])
    return timeline


def main():
    cfg = load_config()

    # paths vindos do config (podem ser relativos)
    outputs_dir = Path(cfg.get("paths", {}).get("outputs", "outputs"))
    reports_dir = Path(cfg.get("paths", {}).get("reports", "reports"))

    # ✅ garante que sejam resolvidos a partir da raiz do projeto
    if not outputs_dir.is_absolute():
        outputs_dir = PROJECT_ROOT / outputs_dir
    if not reports_dir.is_absolute():
        reports_dir = PROJECT_ROOT / reports_dir

    port_scan_path = outputs_dir / "port_scan.json"
    log_report_path = outputs_dir / "log_report.json"
    password_report_path = outputs_dir / "password_report.json"

    # ✅ alertas novos (v1.3+)
    alerts_bf_path = outputs_dir / "alerts_bruteforce.jsonl"
    alerts_cmp_path = outputs_dir / "alerts_compromise.jsonl"

    # ✅ fallback (nomes antigos, se existirem)
    legacy_bf_path = outputs_dir / "soc_alerts.jsonl"
    legacy_cmp_path = outputs_dir / "soc_alerts_compromise.jsonl"

    # ✅ eventos para timeline (outputs -> fallback examples)
    soc_events_auth_path = outputs_dir / "soc_events_auth.jsonl"
    example_events_path = PROJECT_ROOT / "examples" / "ssh_events_sample.jsonl"

    log.info("Iniciando report_builder")
    log.info(f"PROJECT_ROOT: {PROJECT_ROOT}")
    log.info(f"Outputs dir: {outputs_dir} | Reports dir: {reports_dir}")

    port_scan = load_json(port_scan_path)
    log_report = load_json(log_report_path)
    password_report = load_json(password_report_path)

    # carrega alertas (novos -> fallback antigos)
    soc_alerts_bf = load_jsonl(alerts_bf_path) or load_jsonl(legacy_bf_path)
    soc_alerts_cmp = load_jsonl(alerts_cmp_path) or load_jsonl(legacy_cmp_path)

    # ✅ NORMALIZA pro HTML conseguir preencher colunas
    soc_alerts_raw = soc_alerts_bf + soc_alerts_cmp
    soc_alerts = [normalize_alert(a) for a in soc_alerts_raw]

    # eventos para timeline (primeiro outputs, senão examples)
    events = load_jsonl(soc_events_auth_path)
    timeline_source = str(soc_events_auth_path)
    if not events:
        events = load_jsonl(example_events_path)
        timeline_source = str(example_events_path)

    attack_timeline = build_attack_timeline(events, soc_alerts)

    summary = {
        "open_ports": port_scan.get("open_ports") if port_scan else None,
        "failed_logins": log_report.get("failed_attempts") if log_report else None,
        "password_strength": (
            password_report.get("result", {}).get("verdict") if password_report else None
        ),
        "soc_alerts_total": len(soc_alerts),
        "soc_alerts_high_critical": sum(
            1
            for a in soc_alerts
            if str(a.get("severity", "")).lower() in ("high", "critical")
        ),
    }

    final_report = {
        "tool": "security_automation_toolkit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "attack_timeline": attack_timeline,  # ✅ topo (seu template usa isso)
        "summary": summary,
        "details": {
            "port_scan": port_scan,
            "log_analysis": log_report,
            "password_check": password_report,
            "soc_alerts": soc_alerts,
            "attack_timeline": attack_timeline,
            # debug útil (não atrapalha o template)
            "timeline_source": timeline_source,
            "events_loaded": len(events),
            "ips_in_alerts": sorted(
                {
                    (a.get("src_ip") or (a.get("entities") or {}).get("src_ip"))
                    for a in soc_alerts
                    if (a.get("src_ip") or (a.get("entities") or {}).get("src_ip"))
                }
            ),
            "ips_in_events": sorted({e.get("src_ip") for e in events if e.get("src_ip")}),
        },
    }

    reports_dir.mkdir(parents=True, exist_ok=True)
    out_path = reports_dir / "final_report.json"
    out_path.write_text(
        json.dumps(final_report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    log.info("Relatório final gerado com sucesso")
    log.info(f"Arquivo salvo em: {out_path}")
    log.info(
        f"Timeline: {len(attack_timeline)} | events_loaded: {len(events)} | source: {timeline_source}"
    )

    print("Relatório final gerado com sucesso.")
    print(f"Arquivo salvo em: {out_path}")
    print(
        f"Timeline: {len(attack_timeline)} | events_loaded: {len(events)} | source: {timeline_source}"
    )


if __name__ == "__main__":
    main()
