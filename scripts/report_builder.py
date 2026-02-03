import json
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def main():
    outputs_dir = Path("outputs")

    port_scan = load_json(outputs_dir / "port_scan.json")
    log_report = load_json(outputs_dir / "log_report.json")
    password_report = load_json(outputs_dir / "password_report.json")

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

    out_path = outputs_dir / "final_report.json"
    out_path.write_text(json.dumps(final_report, indent=2), encoding="utf-8")

    print("Relatório final gerado com sucesso.")
    print(f"Arquivo salvo em: {out_path}")


if __name__ == "__main__":
    main()
