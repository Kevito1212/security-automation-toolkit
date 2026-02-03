import argparse
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PORTS = [21, 22, 23, 80, 443, 3306]

SERVICE_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "https",
    3306: "mysql",
}


def parse_ports(ports_arg: str | None, use_common: bool) -> list[int]:
    if use_common or not ports_arg:
        return DEFAULT_PORTS

    ports: list[int] = []
    parts = [p.strip() for p in ports_arg.split(",") if p.strip()]

    for p in parts:
        if "-" in p:
            start, end = p.split("-", 1)
            start_i = int(start)
            end_i = int(end)
            if start_i > end_i:
                start_i, end_i = end_i, start_i
            ports.extend(range(start_i, end_i + 1))
        else:
            ports.append(int(p))

    ports = sorted(set([x for x in ports if 1 <= x <= 65535]))
    return ports if ports else DEFAULT_PORTS


def scan_ports(host: str, ports: list[int], timeout: float) -> dict:
    results = []
    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            code = sock.connect_ex((host, port))
            is_open = (code == 0)

            item = {
                "port": port,
                "open": is_open,
                "service_hint": SERVICE_HINTS.get(port),
            }
            results.append(item)

            if is_open:
                open_ports.append(port)

        except socket.gaierror:
            raise ValueError("Host inválido ou não resolvido (DNS).")
        except Exception as e:
            results.append({"port": port, "open": False, "error": str(e)})
        finally:
            sock.close()

    return {"results": results, "open_ports": open_ports}


def main():
    parser = argparse.ArgumentParser(description="Scanner simples de portas TCP (educacional).")
    parser.add_argument("host", help="IP ou hostname do alvo (ex: 127.0.0.1)")
    parser.add_argument("--ports", help="Ex: 22,80,443 ou 1-1024 ou 1-200,443")
    parser.add_argument("--common", action="store_true", help="Usar portas comuns (padrão).")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout em segundos (padrão: 1.0)")
    parser.add_argument("--out", default="outputs/port_scan.json", help="Caminho do arquivo JSON de saída")
    args = parser.parse_args()

    ports = parse_ports(args.ports, args.common or (args.ports is None))
    started_at = datetime.now(timezone.utc).isoformat()

    data = scan_ports(args.host, ports, args.timeout)

    finished_at = datetime.now(timezone.utc).isoformat()
    report = {
        "tool": "port_scanner",
        "host": args.host,
        "started_at": started_at,
        "finished_at": finished_at,
        "ports_scanned": len(ports),
        "open_ports": data["open_ports"],
        "results": data["results"],
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Host analisado: {args.host}")
    print(f"Portas escaneadas: {len(ports)}")
    print(f"Portas abertas: {report['open_ports'] if report['open_ports'] else 'nenhuma'}")
    print(f"Relatório salvo em: {out_path}")


if __name__ == "__main__":
    main()
