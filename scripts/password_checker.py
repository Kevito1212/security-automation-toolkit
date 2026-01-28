common_passwords = ["123456", "admin", "password", "12345678"]

password = input("Digite uma senha para testar: ")

if password in common_passwords:
    print("⚠️ Senha fraca detectada!")
else:
    print("✅ Senha aparentemente segura.")
