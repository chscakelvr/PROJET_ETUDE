"""
Module Diagnostic Reseau - CyberScan
Utilise Nmap pour scanner les ports et services d'une cible.
"""

import subprocess
import re


def run_network_scan(target):
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []

    try:
        result = subprocess.run(
            ["nmap", "-sV", "-T4", "--top-ports", "100", "-oX", "-", clean_target],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout
        ports_found = parse_nmap_xml(output)

        for port_info in ports_found:
            port = port_info["port"]
            state = port_info["state"]
            service = port_info["service"]
            version = port_info.get("version", "")

            if state == "open":
                severity = classify_port_severity(port, service)
                findings.append({
                    "severity": severity,
                    "title": f"Port {port} ({service}) ouvert",
                    "detail": f"Service detecte : {service} {version}. "
                              f"Etat : {state}. "
                              f"{get_port_recommendation(port, service)}",
                })

        open_count = len([p for p in ports_found if p["state"] == "open"])
        closed_count = len([p for p in ports_found if p["state"] == "closed"])
        findings.append({
            "severity": "info",
            "title": f"Scan termine : {open_count} port(s) ouvert(s) sur 100 scannes",
            "detail": f"Scan Nmap effectue sur {clean_target}. "
                      f"{open_count} ouvert(s), {closed_count} ferme(s).",
        })

    except subprocess.TimeoutExpired:
        findings.append({
            "severity": "warning",
            "title": "Scan reseau : timeout",
            "detail": f"Le scan de {clean_target} a depasse le delai de 120 secondes.",
        })
    except FileNotFoundError:
        findings.append({
            "severity": "error",
            "title": "Nmap non installe",
            "detail": "L'outil nmap n'a pas ete trouve. Installez-le avec : sudo apt install nmap",
        })
    except Exception as e:
        findings.append({
            "severity": "error",
            "title": "Erreur lors du scan reseau",
            "detail": str(e),
        })

    return {
        "name": "Diagnostic reseau",
        "findings": findings,
    }


def parse_nmap_xml(xml_output):
    ports = []
    port_pattern = re.compile(
        r'<port protocol="(\w+)" portid="(\d+)">'
        r'<state state="(\w+)"[^/]*/>'
        r'(?:<service name="([^"]*)"[^/]*(?:product="([^"]*)")?[^/]*(?:version="([^"]*)")?[^/]*/?>)?',
        re.DOTALL,
    )

    for match in port_pattern.finditer(xml_output):
        protocol, port_id, state, service, product, version = match.groups()
        ports.append({
            "port": int(port_id),
            "protocol": protocol,
            "state": state,
            "service": service or "unknown",
            "version": f"{product or ''} {version or ''}".strip(),
        })

    return ports


def classify_port_severity(port, service):
    critical_ports = {21, 23, 3389, 445}
    high_ports = {22, 3306, 5432, 27017}
    medium_ports = {80, 8080, 8443}

    if port in critical_ports:
        return "critical"
    elif port in high_ports:
        return "high"
    elif port in medium_ports:
        return "medium"
    elif service in ("telnet", "ftp", "rlogin"):
        return "critical"
    else:
        return "low"


def get_port_recommendation(port, service):
    recommendations = {
        21: "FTP est un protocole non chiffre. Recommandation : utiliser SFTP (port 22) a la place.",
        22: "SSH est expose. Recommandation : restreindre l'acces par IP, desactiver root login, utiliser des cles SSH.",
        23: "Telnet transmet les donnees en clair. Recommandation : desactiver immediatement et utiliser SSH.",
        25: "SMTP ouvert. Verifier qu'il n'est pas un relais ouvert (open relay).",
        80: "HTTP sans chiffrement. Recommandation : rediriger vers HTTPS (port 443).",
        443: "HTTPS actif. Verifier la validite du certificat SSL/TLS.",
        445: "SMB expose. Risque eleve d'exploitation (EternalBlue). Recommandation : bloquer depuis l'exterieur.",
        3306: "MySQL expose. Recommandation : ne jamais exposer la base de donnees sur Internet.",
        3389: "RDP expose. Risque de brute force. Recommandation : VPN obligatoire ou desactivation.",
        5432: "PostgreSQL expose. Recommandation : restreindre l'acces reseau.",
        8080: "Port HTTP alternatif. Verifier qu'aucune interface d'administration n'est exposee.",
        27017: "MongoDB expose. Verifier que l'authentification est activee.",
    }
    return recommendations.get(port, "Verifier la necessite de ce service et restreindre l'acces si possible.")
