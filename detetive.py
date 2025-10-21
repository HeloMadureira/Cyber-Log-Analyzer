import pandas as pd
import re


print("--- [ ANÁLISE DO ACCESS.LOG (WEB) ] ---")

try:

    colunas = ['ip', 'identd', 'user', 'timestamp', 'request', 'status', 'bytes', 'referer', 'user_agent']


    df_access = pd.read_csv(
        "access.log",
        sep=r'\s+',       
        engine='python',
        names=colunas,
        on_bad_lines='skip', 
        header=None
    )


    print("\n[+] IPs mais ativos (possíveis scanners):")
    ip_counts = df_access['ip'].value_counts()
    print(ip_counts.head(5))


    df_access['user_agent'] = df_access['user_agent'].astype(str)

    ataques_nikto = df_access[df_access['user_agent'].str.contains('nikto', case=False, na=False)]

    if not ataques_nikto.empty:

        ip_atacante_nikto = ataques_nikto['ip'].iloc[0]
        print(f"\n[!!!] ATAQUE 'Nikto' DETECTADO!")
        print(f"      IP do Atacante: {ip_atacante_nikto}")
    else:
        print("\n[-] Nenhum ataque 'Nikto' óbvio encontrado.")

except Exception as e:
    print(f"[!] Erro ao ler ou analisar o access.log: {e}")


print("\n\n--- [ ANÁLISE DO AUTH.LOG (SSH) ] ---")

try:


    with open("auth.log", "r") as f:
        linhas = f.readlines()

    failed_logins = {}
    for linha in linhas:
        if "Failed password" in linha:

            match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', linha)
            if match:
                ip = match.group(1)
               
                failed_logins[ip] = failed_logins.get(ip, 0) + 1

    if failed_logins:
        print("\n[+] Contagem de falhas de login SSH por IP:")
        for ip, contagem in failed_logins.items():
            print(f"      IP: {ip}  |  Tentativas Falhas: {contagem}")
            if contagem > 4:
                print(f"      [!!!] POSSÍVEL ATAQUE DE BRUTE FORCE DETECTADO DO IP: {ip}")
    else:
        print("\n[-] Nenhuma falha de login SSH (Failed password) encontrada.")

except Exception as e:
    print(f"[!] Erro ao ler ou analisar o auth.log: {e}")

print("\n--- [ FIM DA ANÁLISE ] ---")
