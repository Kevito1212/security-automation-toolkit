import argparse
import subprocess
import sys
from pathlib import Path


def run_script(script_name: str, extra_args: list[str]):
    scripts_dir = Path("scripts")
    script_path = scripts_dir / script_name

    if not script_path.exists():
        print(f"Script não encontrado: {script_path}")
        sys.exit(1)

    # Usa o mesmo interpretador Python do CLI
    cmd = [sys.executable, str(script_path)] + extra_args
    print(f"Executando: {' '.join(cmd)}")

    result = subprocess.run(cmd)

    if result.returncode != 0:
        print(f"Erro ao executar {script_name} (code {result.returncode})")
        sys.exit(result.returncode)


def main():
    parser = argparse.ArgumentParser(
        prog="sat",
        description="Security Automation Toolkit CLI"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Comandos básicos
    sub.add_parser("ping", help="Teste rápido do CLI")
    sub.add_parser("list-outputs", help="Lista arquivos gerados em outputs/")

    # Comando run
    run = sub.add_parser("run", help="Executa um módulo do toolkit via scripts/")
    run.add_argument(
        "module",
        choices=["password", "portscan", "report"],
        help="Módulo para executar"
    )
    run.add_argument(
        "args",
        nargs="*",
        help="Argumentos adicionais repassados ao script"
    )

    args = parser.parse_args()

    if args.cmd == "ping":
        print("SAT CLI OK")

    elif args.cmd == "list-outputs":
        out = Path("outputs")
        if not out.exists():
            print("Pasta outputs não encontrada")
            return

        files = list(out.glob("*"))
        if not files:
            print("Nenhum output encontrado")
            return

        print("Arquivos de saída:")
        for f in files:
            print("-", f.name)

    elif args.cmd == "run":
        mapping = {
            "password": "password_checker.py",
            "portscan": "port_scanner.py",
            "report": "report_builder.py",
        }
        run_script(mapping[args.module], args.args)


if __name__ == "__main__":
    main()