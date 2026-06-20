"""
Module Forensique - CyberScan
Analyse un fichier suspect : hash MD5/SHA256 + verification VirusTotal API.
"""

import hashlib
import os
import requests


def analyze_file(file_path: str, vt_api_key: str) -> dict:
    """
    Analyse un fichier suspect :
    - Calcule MD5 et SHA256
    - Interroge VirusTotal pour savoir si le fichier est connu comme malveillant
    """
    findings = []

    if not os.path.exists(file_path):
        return {
            "name": "Analyse forensique",
            "findings": [{
                "severity": "error",
                "title": "Fichier introuvable",
                "detail": f"Le fichier {file_path} n'existe pas.",
            }],
        }

    # --- Calcul des hashes ---
    md5, sha256 = compute_hashes(file_path)
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)

    findings.append({
        "severity": "info",
        "title": f"Fichier analyse : {file_name}",
        "detail": f"Taille : {file_size} octets | MD5 : {md5} | SHA256 : {sha256}",
    })

    # --- Verification VirusTotal ---
    if vt_api_key:
        findings.extend(check_virustotal(sha256, vt_api_key, file_name))
    else:
        findings.append({
            "severity": "warning",
            "title": "Cle API VirusTotal manquante",
            "detail": "Ajoutez VIRUSTOTAL_API_KEY dans votre fichier .env pour activer la verification en ligne.",
        })

    return {
        "name": "Analyse forensique",
        "findings": findings,
    }


def compute_hashes(file_path: str):
    """Calcule MD5 et SHA256 d'un fichier."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def check_virustotal(sha256: str, api_key: str, file_name: str) -> list:
    """Interroge l'API VirusTotal avec le hash SHA256 du fichier."""
    findings = []

    try:
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"

        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + undetected + stats.get("harmless", 0)

            if malicious > 0:
                severity = "critical" if malicious > 5 else "high"
                findings.append({
                    "severity": severity,
                    "title": f"Fichier malveillant detecte par VirusTotal",
                    "detail": f"{malicious}/{total} moteurs antivirus ont detecte ce fichier comme malveillant. "
                              f"Recommandation : isoler et supprimer immediatement ce fichier.",
                })
            elif suspicious > 0:
                findings.append({
                    "severity": "medium",
                    "title": f"Fichier suspect sur VirusTotal",
                    "detail": f"{suspicious}/{total} moteurs le considerent suspect. Analyse approfondie recommandee.",
                })
            else:
                findings.append({
                    "severity": "info",
                    "title": "Fichier propre selon VirusTotal",
                    "detail": f"0/{total} moteurs antivirus ont detecte une menace sur ce fichier.",
                })

        elif response.status_code == 404:
            # Hash inconnu de VT : on upload le fichier
            findings.append({
                "severity": "info",
                "title": "Hash inconnu de VirusTotal",
                "detail": f"Le fichier '{file_name}' n'est pas encore repertorie dans la base VirusTotal. "
                          f"Il peut s'agir d'un fichier recent ou peu repandu.",
            })

        elif response.status_code == 401:
            findings.append({
                "severity": "error",
                "title": "Cle API VirusTotal invalide",
                "detail": "Verifiez votre VIRUSTOTAL_API_KEY dans le fichier .env.",
            })

        else:
            findings.append({
                "severity": "warning",
                "title": f"VirusTotal : reponse inattendue (HTTP {response.status_code})",
                "detail": "Impossible d'obtenir un resultat. Reessayez plus tard.",
            })

    except requests.exceptions.Timeout:
        findings.append({
            "severity": "warning",
            "title": "VirusTotal : timeout",
            "detail": "La requete vers VirusTotal a depasse le delai. Verifiez votre connexion.",
        })
    except Exception as e:
        findings.append({
            "severity": "error",
            "title": "Erreur VirusTotal",
            "detail": str(e),
        })

    return findings
