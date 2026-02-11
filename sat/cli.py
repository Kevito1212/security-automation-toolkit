import argparse
import os
import subprocess
import sys
from pathlib import Path

from sat.utils.config_loader import load_config
from sat.utils.logger import setup_logger, get_logger


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

    sub.add_parser("ping", help="Teste rápido do CLI")
    sub.add_parser("list-outputs", help="Lista arquivos gerados em outputs/")

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

    args = parser.parse_args()
    log.info(f"Args received: {args}")

    scripts_dir = Path(cfg.get("paths", {}).get("scripts", "scripts"))
    outputs_dir = Path(cfg.get("paths", {}).get("outputs", "outputs"))

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
