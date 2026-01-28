import socket

target = input("Digite o IP ou host: ")

ports = [21, 22, 23, 80, 443, 3306]

print(f"\nEscaneando o alvo: {target}\n")

for port in ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    result = sock.connect_ex((target, port))

    if result == 0:
        print(f"[ABERTA] Porta {port}")
    else:
        print(f"[FECHADA] Porta {port}")

    sock.close()
