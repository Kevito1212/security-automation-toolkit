import argparse
import os
import subprocess
import sys
from pathlib import Path

from sat.utils.config_loader import load_config
from sat.utils.logger import setup_logger, get_logger
from sat.soc.ingest import ingest_auth_log
from sat.soc.detection import detect_bruteforce_window, detect_possible_compromise


def run_script(script_path: Path, extra_args: list[str], log):
    if not script_path.exists():
        log.error(f"Script não encontrado: {script_path}")
        sys.exit(1)

    cmd = [sys.executable, str(script_path)] + extra_args
    log.info(f"Executando: {' '.join(cmd)}")

    # garante que o subprocess enxergue o pacote "sat"
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")

    result = subprocess.run(cmd, env=env)

    if result.returncode != 0:
        log.error(f"Erro ao executar {script_path.name} (code {result.returncode})")
        sys.exit(result.returncode)

    log.info(f"Execução finalizada com sucesso: {script_path.name}")


def main():
    cfg = load_config()
    setup_logger(cfg)
    log = get_logger("cli")

    parser = argparse.ArgumentParser(
        prog="sat",
        description="Security Automation Toolkit CLI"
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    # ===== COMANDOS BÁSICOS =====
    sub.add_parser("ping", help="Teste rápido do CLI")
    sub.add_parser("list-outputs", help="Lista arquivos gerados em outputs/")

    scripts_dir = Path(cfg.get("paths", {}).get("scripts", "scripts"))
    outputs_dir = Path(cfg.get("paths", {}).get("outputs", "outputs"))

    # ===== SOC INGEST =====
    ingest = sub.add_parser("ingest", help="SOC: ingere logs e gera eventos normalizados (JSONL)")
    ingest_sub = ingest.add_subparsers(dest="source", required=True)

    ingest_auth = ingest_sub.add_parser("auth", help="Ingere auth_sample.log (SSH/sudo)")
    ingest_auth.add_argument(
        "--input",
        default="auth_sample.log",
        help="Nome do arquivo (dentro de scripts/) ou caminho completo"
    )
    ingest_auth.add_argument(
        "--output",
        default="soc_events_auth.jsonl",
        help="Nome do arquivo (dentro de outputs/) ou caminho completo"
    )

    # ===== SOC DETECT =====
    detect = sub.add_parser("detect", help="SOC: executa regras de detecção")
    detect_sub = detect.add_subparsers(dest="rule", required=True)

    bf = detect_sub.add_parser("bruteforce", help="Detecta brute force SSH (sliding window)")
    bf.add_argument("--input", default="soc_events_auth.jsonl")
    bf.add_argument("--output", default="soc_alerts.jsonl")
    bf.add_argument("--threshold", type=int, default=5)
    bf.add_argument("--window", type=int, default=120, help="Janela em segundos (ex: 120 = 2 min)")

    cmp = detect_sub.add_parser("compromise", help="Detecta possível comprometimento (falhas -> sucesso)")
    cmp.add_argument("--input", default="soc_events_auth.jsonl")
    cmp.add_argument("--output", default="soc_alerts_compromise.jsonl")
    cmp.add_argument("--threshold", type=int, default=5)
    cmp.add_argument("--window", type=int, default=120, help="Janela em segundos (ex: 120 = 2 min)")

    # ===== COMANDO RUN =====
    run = sub.add_parser("run", help="Executa um módulo do toolkit via scripts/")
    run.add_argument(
        "module",
        choices=["password", "portscan", "report", "loganalyzer"],
        help="Módulo para executar"
    )

    # Flags globais do comando run (usadas principalmente pelo módulo report)
    run.add_argument(
        "--html",
        action="store_true",
        help="(Somente report) Gera também o relatório em HTML"
    )
    run.add_argument(
        "--template",
        default="reports/report_template.html",
        help="(Somente report) Caminho do template HTML (Jinja2)"
    )
    run.add_argument(
        "--output-html",
        default="reports/report.html",
        help="(Somente report) Caminho do arquivo HTML final"
    )
    run.add_argument(
        "--final-json",
        default="reports/final_report.json",
        help="(Somente report) Caminho do JSON consolidado usado para renderizar HTML"
    )

    run.add_argument(
        "args",
        nargs="*",
        help="Argumentos adicionais repassados ao script"
    )

    # ===== PARSE =====
    args = parser.parse_args()
    log.info(f"Args received: {args}")

    # ===== EXECUÇÃO =====
    if args.cmd == "ping":
        log.info("SAT CLI OK")
        print("SAT CLI OK")

    elif args.cmd == "list-outputs":
        if not outputs_dir.exists():
            log.warning(f"Pasta outputs não encontrada: {outputs_dir}")
            print("Pasta outputs não encontrada")
            return

        files = [p for p in outputs_dir.rglob("*") if p.is_file()]
        if not files:
            log.info("Nenhum output encontrado")
            print("Nenhum output encontrado")
            return

        log.info(f"Listando outputs ({len(files)} arquivo(s))")
        print("Arquivos de saída:")
        for f in files:
            print("-", f.relative_to(outputs_dir))

    elif args.cmd == "ingest":
        if args.source == "auth":
            input_path = Path(args.input)
            if not input_path.exists():
                input_path = scripts_dir / args.input

            output_path = Path(args.output)
            if output_path.parent == Path("."):
                output_path = outputs_dir / args.output

            total = ingest_auth_log(str(input_path), str(output_path))
            log.info(f"[SOC] {total} evento(s) gerado(s) em {output_path}")
            print(f"[SOC] {total} evento(s) gerado(s) em {output_path}")

    elif args.cmd == "detect":
        input_path = Path(args.input)
        if input_path.parent == Path("."):
            input_path = outputs_dir / args.input

        output_path = Path(args.output)
        if output_path.parent == Path("."):
            output_path = outputs_dir / args.output

        if args.rule == "bruteforce":
            total = detect_bruteforce_window(
                str(input_path),
                str(output_path),
                threshold=args.threshold,
                window_seconds=args.window
            )
            log.info(f"[SOC] {total} alerta(s) gerado(s) em {output_path}")
            print(f"[SOC] {total} alerta(s) gerado(s) em {output_path}")

        elif args.rule == "compromise":
            total = detect_possible_compromise(
                input_path,
                output_path,
                threshold=args.threshold,
                window_seconds=args.window
            )
            log.info(f"[SOC] {total} alerta(s) gerado(s) em {output_path}")
            print(f"[SOC] {total} alerta(s) gerado(s) em {output_path}")

    elif args.cmd == "run":
        mapping = {
            "password": "password_checker.py",
            "portscan": "port_scanner.py",
            "report": "report_builder.py",
            "loganalyzer": "log_analyzer.py",
        }

        script_name = mapping[args.module]
        script_path = scripts_dir / script_name

        # 1) roda o script do módulo normalmente
        run_script(script_path, args.args, log)

        # 2) se for report e pediu --html, renderiza HTML após gerar o JSON
        if args.module == "report" and args.html:
            try:
                from sat.utils.html_renderer import render_html_report
            except Exception as e:
                log.error(f"Falha ao importar html_renderer: {e}")
                sys.exit(1)

            final_json = Path(args.final_json)
            template_path = Path(args.template)
            output_html = Path(args.output_html)

            try:
                out = render_html_report(
                    final_report_json=final_json,
                    template_path=template_path,
                    output_html=output_html,
                )
                log.info(f"HTML gerado em: {out}")
                print(f"[OK] HTML gerado em: {out}")
            except Exception as e:
                log.error(f"Falha ao gerar HTML: {e}")
                sys.exit(1)


if __name__ == "__main__":
    main()
    