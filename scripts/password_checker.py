import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

COMMON_PASSWORDS = {
    "123456", "12345678", "password", "admin", "qwerty", "senha123"
}


def check_password(password: str) -> dict:
    score = 0
    reasons = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        reasons.append("Senha muito curta (recomendado 12+ caracteres).")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        reasons.append("Sem letra maiúscula.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        reasons.append("Sem letra minúscula.")

    if re.search(r"\d", password):
        score += 1
    else:
        reasons.append("Sem número.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        reasons.append("Sem caractere especial.")

    if password.lower() in COMMON_PASSWORDS:
        reasons.append("Senha está na lista de senhas comuns.")
        score = 0

    if score >= 6:
        verdict = "forte"
    elif score >= 4:
        verdict = "media"
    else:
        verdict = "fraca"

    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons
    }


def main():
    parser = argparse.ArgumentParser(
        description="Verificador simples de força de senha (educacional)."
    )
    parser.add_argument(
        "--out",
        default="outputs/password_report.json",
        help="Caminho do arquivo JSON de saída"
    )
    args = parser.parse_args()

    password = input("Digite a senha para análise: ")
    result = check_password(password)

    report = {
        "tool": "password_checker",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "result": result
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Resultado: {result['verdict']} (score: {result['score']})")
    if result["reasons"]:
        print("Observações:")
        for r in result["reasons"]:
            print(f"- {r}")
    print(f"Relatório salvo em: {out_path}")


if __name__ == "__main__":
    main()
