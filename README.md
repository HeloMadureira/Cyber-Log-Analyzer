# 🕵️ Python Log Analyzer (Detetive de Logs)

Este é um projeto de Cibersegurança Defensiva ("Blue Team") que utiliza Análise de Dados com Python e Pandas para detectar atividades maliciosas em arquivos de log de um servidor.

O projeto simula um cenário real onde um analista de segurança (SOC) investiga logs coletados de um servidor comprometido para identificar a origem e o tipo de ataque.

![Badge de Linguagem](https://img.shields.io/badge/Python-3.x-blue.svg)
![Badge de Biblioteca](https://img.shields.io/badge/Library-Pandas-blueviolet.svg)

---

## 🎯 Metodologia do Projeto

Este projeto foi dividido em três fases, simulando o ciclo completo de um incidente de segurança:

### 1. Fase de Ataque (Red Team)
* **Máquina Atacante:** Kali Linux
* **Máquina Alvo:** Metasploitable 2
* **Ações:** Foi gerado "barulho" intencional no alvo para criar logs, utilizando:
    * `nmap -A -p- -Pn`: Scan de rede agressivo em todas as 65.535 portas.
    * `nikto`: Scan de vulnerabilidades web, gerando centenas de logs no Apache.
    * `ssh_brute.py`: Script de força bruta contra a porta 22 (SSH).

### 2. Fase de Coleta (Forese)
* Os logs de evidência (`access.log` do Apache e `auth.log` do SSH) foram coletados da máquina Metasploitable usando `scp` (Secure Copy), contornando problemas de compatibilidade de SSH (`-o HostKeyAlgorithms=+ssh-rsa`).

### 3. Fase de Análise (Blue Team)
* O script `detetive.py` (este projeto) foi executado na máquina Kali.
* **Análise do `access.log`:** O script usa **Pandas** para ler o log "sujo" do Apache, pular linhas corrompidas (`on_bad_lines='skip'`) e agregar os dados para encontrar o IP mais ativo.
* **Análise do `auth.log`:** O script usa `regex` para "parsear" (ler) o log de autenticação, contar o número de `"Failed password"` por IP e disparar um alarme se o limite for ultrapassado.

## 🚀 Como Usar

1.  **Instale as dependências** (em um sistema baseado em Debian/Kali):
    ```bash
    sudo apt install python3-pandas python3-matplotlib
    ```
2.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/HeloMadureira/Cyber-Log-Analyzer.git](https://github.com/HeloMadureira/Cyber-Log-Analyzer.git)
    cd Cyber-Log-Analyzer
    ```
3.  **Adicione os Logs:** Coloque seus arquivos `access.log` e `auth.log` na mesma pasta do script.
4.  **Execute o detetive:**
    ```bash
    python3 detetive.py
    ```

## ⚠️ Aviso Legal

Este projeto foi criado **APENAS para fins educacionais** em um ambiente de laboratório privado. As ferramentas e técnicas aqui demonstradas não devem ser usadas em sistemas ou redes sem autorização explícita.
