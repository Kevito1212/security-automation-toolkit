import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def main():
    parser = argparse.ArgumentParser(
        description="Analisador simples de logs de autenticação (educacional)."
    )
    parser.add_argument(
        "--file",
        default="scripts/auth.log",
        help="Caminho do arquivo de log (padrão: scripts/auth.log)",
    )
    parser.add_argument(
        "--keyword",
        default="failed",
        help="Palavra-chave para identificar falhas (padrão: failed)",
    )
    parser.add_argument(
        "--out",
        default="outputs/log_report.json",
        help="Caminho do arquivo JSON de saída (padrão: outputs/log_report.json)",
    )
    args = parser.parse_args()

    log_path = Path(args.file)
    if not log_path.exists():
        print(f"[ERRO] Arquivo não encontrado: {log_path}")
        return

    failed_attempts = 0
    ip_counts = Counter()

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if args.keyword.lower() in line.lower():
                failed_attempts += 1
                m = IP_RE.search(line)
                if m:
                    ip_counts[m.group(0)] += 1

    top_ip, top_count = (None, 0)
    if ip_counts:
        top_ip, top_count = ip_counts.most_common(1)[0]

    report = {
        "tool": "log_analyzer",
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "file": str(log_path),
        "keyword": args.keyword,
        "failed_attempts": failed_attempts,
        "top_suspicious_ip": top_ip,
        "top_suspicious_ip_count": top_count,
        "ip_counts": dict(ip_counts),
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Arquivo analisado: {log_path}")
    print(f"Falhas detectadas: {failed_attempts}")
    if top_ip:
        print(f"IP com mais falhas: {top_ip} ({top_count})")
    print(f"Relatório salvo em: {out_path}")


if __name__ == "__main__":
    main()
