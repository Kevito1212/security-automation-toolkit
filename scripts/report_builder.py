import json
from datetime import datetime, timezone
from pathlib import Path

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


def main():
    cfg = load_config()

    outputs_dir = Path(cfg.get("paths", {}).get("outputs", "outputs"))
    reports_dir = Path(cfg.get("paths", {}).get("reports", "reports"))

    port_scan_path = outputs_dir / "port_scan.json"
    log_report_path = outputs_dir / "log_report.json"
    password_report_path = outputs_dir / "password_report.json"

    log.info("Iniciando report_builder")
    log.info(f"Outputs dir: {outputs_dir} | Reports dir: {reports_dir}")

    port_scan = load_json(port_scan_path)
    log_report = load_json(log_report_path)
    password_report = load_json(password_report_path)

    summary = {
        "open_ports": port_scan.get("open_ports") if port_scan else None,
        "failed_logins": log_report.get("failed_attempts") if log_report else None,
        "password_strength": (
            password_report.get("result", {}).get("verdict")
            if password_report else None
        ),
    }

    final_report = {
        "tool": "security_automation_toolkit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "details": {
            "port_scan": port_scan,
            "log_analysis": log_report,
            "password_check": password_report,
        },
    }

    reports_dir.mkdir(parents=True, exist_ok=True)
    out_path = reports_dir / "final_report.json"
    out_path.write_text(json.dumps(final_report, indent=2), encoding="utf-8")

    log.info("Relatório final gerado com sucesso")
    log.info(f"Arquivo salvo em: {out_path}")

    print("Relatório final gerado com sucesso.")
    print(f"Arquivo salvo em: {out_path}")


if __name__ == "__main__":
    main()
