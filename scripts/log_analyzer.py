failed_attempts = 0

with open("scripts/auth.log", "r") as file:
    for line in file:
        if "failed" in line.lower():
            failed_attempts += 1

print(f"Tentativas de login falhadas detectadas: {failed_attempts}")
