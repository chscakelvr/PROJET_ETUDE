"""
Module Diagnostic Securite Infrastructure - CyberScan
Teste la robustesse des services via Hydra (brute force).
"""

import subprocess
import re
import os


def run_infra_scan(target):
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    findings = []
    findings.extend(run_hydra_ssh(clean_target))
    findings.extend(run_hydra_ftp(clean_target))
    findings.extend(check_ftp_anonymous(clean_target))

    return {
        "name": "Diagnostic securite infrastructure",
        "findings": findings,
    }


def get_wordlist_path():
    paths = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/metasploit/common_passwords.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    ]
    for path in paths:
        if os.path.exists(path):
            return path

    fallback = "/tmp/cyberscan_wordlist.txt"
    if not os.path.exists(fallback):
        common_passwords = [
            "admin", "password", "123456", "admin123", "root",
            "toor", "password123", "letmein", "welcome", "monkey",
            "dragon", "master", "qwerty", "login", "abc123",
            "starwars", "trustno1", "iloveyou", "shadow", "123456789",
        ]
        with open(fallback, "w") as f:
            f.write("\n".join(common_passwords))
    return fallback


def get_users_list():
    return ["admin", "root", "user", "test", "ftp", "guest"]


def run_hydra_ssh(target):
    findings = []

    try:
        wordlist = get_wordlist_path()

        result = subprocess.run(
            [
                "hydra", "-L", "-", "-P", wordlist,
                "-t", "4", "-f", "-V",
                "-o", "/tmp/hydra_ssh_results.txt",
                f"ssh://{target}",
            ],
            input="\n".join(get_users_list()),
            capture_output=True,
            text=True,
            timeout=120,
        )

        output = result.stdout + result.stderr

        creds_found = re.findall(
            r"\[22\]\[ssh\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)",
            output,
        )

        if creds_found:
            for user, passwd in creds_found:
                findings.append({
                    "severity": "critical",
                    "title": f"Identifiants SSH faibles detectes",
                    "detail": f"L'utilisateur '{user}' utilise un mot de passe trivial. "
                              f"Recommandation : changer immediatement le mot de passe, "
                              f"desactiver l'authentification par mot de passe et utiliser des cles SSH.",
                })
        else:
            if "connect" in output.lower() and "error" not in output.lower():
                findings.append({
                    "severity": "info",
                    "title": "Brute force SSH : aucun identifiant faible detecte",
                    "detail": "Les mots de passe testes n'ont pas permis de se connecter.",
                })
            elif "connection refused" in output.lower():
                findings.append({
                    "severity": "info",
                    "title": "Service SSH non accessible",
                    "detail": f"Le port 22 (SSH) est ferme ou filtre sur {target}.",
                })

    except subprocess.TimeoutExpired:
        findings.append({
            "severity": "warning",
            "title": "Test SSH : timeout",
            "detail": "Le test de brute force SSH a depasse le delai.",
        })
    except FileNotFoundError:
        findings.append({
            "severity": "error",
            "title": "Hydra non installe",
            "detail": "L'outil hydra n'a pas ete trouve. Installez-le avec : sudo apt install hydra",
        })
    except Exception as e:
        findings.append({
            "severity": "error",
            "title": "Erreur lors du test SSH",
            "detail": str(e),
        })

    return findings


def run_hydra_ftp(target):
    findings = []

    try:
        wordlist = get_wordlist_path()

        result = subprocess.run(
            [
                "hydra", "-L", "-", "-P", wordlist,
                "-t", "4", "-f",
                f"ftp://{target}",
            ],
            input="\n".join(get_users_list()),
            capture_output=True,
            text=True,
            timeout=120,
        )

        output = result.stdout + result.stderr

        creds_found = re.findall(
            r"\[21\]\[ftp\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)",
            output,
        )

        if creds_found:
            for user, passwd in creds_found:
                findings.append({
                    "severity": "critical",
                    "title": f"Identifiants FTP faibles detectes",
                    "detail": f"L'utilisateur '{user}' a un mot de passe faible. Recommandation : desactiver FTP et utiliser SFTP a la place.",
                })
        elif "connection refused" in output.lower():
            findings.append({
                "severity": "info",
                "title": "Service FTP non accessible",
                "detail": f"Le port 21 (FTP) est ferme sur {target}.",
            })

    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return findings


def check_ftp_anonymous(target):
    findings = []

    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(target, 21, timeout=10)
        ftp.login("anonymous", "test@test.com")
        ftp.quit()

        findings.append({
            "severity": "high",
            "title": "FTP : connexion anonyme autorisee",
            "detail": "Le serveur FTP accepte les connexions anonymes. Recommandation : desactiver l'acces anonyme.",
        })
    except Exception:
        pass

    return findings
