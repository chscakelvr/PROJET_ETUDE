"""
Module Diagnostic Web & API - CyberScan
Verifie les en-tetes de securite HTTP, teste les injections SQL via SQLmap,
et teste les endpoints API communs pour detecter des acces non authentifies.
"""

import subprocess
import re
import urllib.request
import urllib.error
import ssl


def run_web_scan(target):
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    findings = []
    findings.extend(check_security_headers(target))
    findings.extend(check_ssl_certificate(target))
    findings.extend(check_api_endpoints(target))
    findings.extend(run_sqlmap(target))

    return {
        "name": "Diagnostic web & API",
        "findings": findings,
    }


def check_api_endpoints(target):
    """
    Teste des endpoints API communs pour detecter des acces non authentifies,
    des donnees sensibles exposees ou des mauvaises configurations REST.
    """
    findings = []

    api_paths = [
        "/api", "/api/v1", "/api/v2", "/api/users", "/api/admin",
        "/api/config", "/api/health", "/api/status",
        "/swagger.json", "/openapi.json", "/swagger-ui.html",
        "/api-docs", "/graphql", "/rest", "/wp-json",
    ]

    sensitive_keywords = [
        "password", "passwd", "token", "secret", "api_key",
        "private_key", "auth", "credential", "database", "admin",
    ]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    accessible_endpoints = []
    exposed_data_endpoints = []
    doc_endpoints = []

    base = target.rstrip("/")

    for path in api_paths:
        url = base + path
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "CyberScan/1.0 Security Audit Tool")
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                status = resp.status
                content_type = resp.headers.get("Content-Type", "")
                body = resp.read(2048).decode("utf-8", errors="ignore").lower()

                if status == 200:
                    if any(d in path for d in ["swagger", "openapi", "api-docs", "graphql"]):
                        doc_endpoints.append(path)
                    else:
                        accessible_endpoints.append(path)

                    if "application/json" in content_type:
                        found_keys = [k for k in sensitive_keywords if k in body]
                        if found_keys:
                            exposed_data_endpoints.append((path, found_keys))

        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                findings.append({
                    "severity": "info",
                    "title": f"Endpoint API protege : {path}",
                    "detail": f"L'endpoint retourne HTTP {e.code} — acces refuse correctement.",
                })
        except Exception:
            pass

    if accessible_endpoints:
        for ep in accessible_endpoints:
            findings.append({
                "severity": "high",
                "title": f"Endpoint API accessible sans authentification : {ep}",
                "detail": f"L'endpoint '{ep}' repond HTTP 200 sans token ni session. "
                          f"Recommandation : proteger avec une authentification (JWT, API key, OAuth2).",
            })
    else:
        findings.append({
            "severity": "info",
            "title": "Aucun endpoint API non protege detecte",
            "detail": f"Les {len(api_paths)} endpoints testes ne sont pas accessibles sans authentification.",
        })

    if doc_endpoints:
        for ep in doc_endpoints:
            findings.append({
                "severity": "medium",
                "title": f"Documentation API exposee publiquement : {ep}",
                "detail": f"L'interface '{ep}' est accessible sans restriction. "
                          f"Elle peut reveler l'architecture interne de l'API. "
                          f"Recommandation : restreindre l'acces en production.",
            })

    if exposed_data_endpoints:
        for ep, keys in exposed_data_endpoints:
            findings.append({
                "severity": "critical",
                "title": f"Donnees sensibles exposees dans la reponse API : {ep}",
                "detail": f"La reponse JSON de '{ep}' contient des champs potentiellement sensibles : "
                          f"{', '.join(keys)}. Recommandation : ne jamais exposer ces champs dans les reponses publiques.",
            })

    return findings


def check_security_headers(target):
    findings = []
    security_headers = {
        "X-Frame-Options": {
            "severity": "high",
            "detail_missing": "Protection contre le clickjacking absente. Recommandation : ajouter 'X-Frame-Options: DENY' ou 'SAMEORIGIN'.",
            "detail_present": "Protection contre le clickjacking active.",
        },
        "Content-Security-Policy": {
            "severity": "high",
            "detail_missing": "Aucune politique CSP definie. Risque de XSS et d'injection de contenu.",
            "detail_present": "Politique de securite du contenu definie.",
        },
        "X-Content-Type-Options": {
            "severity": "medium",
            "detail_missing": "Le navigateur peut interpreter les fichiers differemment. Recommandation : ajouter 'X-Content-Type-Options: nosniff'.",
            "detail_present": "Protection contre le MIME sniffing active.",
        },
        "Strict-Transport-Security": {
            "severity": "high",
            "detail_missing": "HSTS absent. Le site est vulnerable aux attaques de downgrade SSL.",
            "detail_present": "HSTS actif - communication forcee en HTTPS.",
        },
        "X-XSS-Protection": {
            "severity": "medium",
            "detail_missing": "Protection XSS du navigateur non activee.",
            "detail_present": "Protection XSS du navigateur activee.",
        },
        "Referrer-Policy": {
            "severity": "low",
            "detail_missing": "Politique de referent non definie. Les URLs de navigation peuvent fuiter.",
            "detail_present": "Politique de referent definie.",
        },
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(target, method="GET")
        req.add_header("User-Agent", "CyberScan/1.0 Security Audit Tool")

        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            headers = dict(response.headers)

            for header_name, info in security_headers.items():
                header_value = headers.get(header_name)
                if header_value:
                    findings.append({
                        "severity": "info",
                        "title": f"En-tete {header_name} present",
                        "detail": f"{info['detail_present']} Valeur : {header_value}",
                    })
                else:
                    findings.append({
                        "severity": info["severity"],
                        "title": f"En-tete {header_name} manquant",
                        "detail": info["detail_missing"],
                    })

            server_header = headers.get("Server", "")
            if server_header and any(v in server_header.lower() for v in ["apache", "nginx", "iis"]):
                findings.append({
                    "severity": "medium",
                    "title": "Version du serveur exposee",
                    "detail": f"Le header Server revele : '{server_header}'. Recommandation : masquer la version du serveur.",
                })

            set_cookie = headers.get("Set-Cookie", "")
            if set_cookie:
                if "secure" not in set_cookie.lower():
                    findings.append({
                        "severity": "medium",
                        "title": "Cookie sans attribut Secure",
                        "detail": "Un cookie est transmis sans l'attribut Secure.",
                    })
                if "httponly" not in set_cookie.lower():
                    findings.append({
                        "severity": "medium",
                        "title": "Cookie sans attribut HttpOnly",
                        "detail": "Un cookie est accessible via JavaScript. Risque de vol de session par XSS.",
                    })

    except urllib.error.URLError as e:
        findings.append({
            "severity": "warning",
            "title": "Impossible de se connecter a la cible",
            "detail": f"Erreur de connexion a {target} : {str(e.reason)}",
        })
    except Exception as e:
        findings.append({
            "severity": "error",
            "title": "Erreur lors du scan des en-tetes",
            "detail": str(e),
        })

    return findings


def check_ssl_certificate(target):
    findings = []

    if not target.startswith("https://"):
        findings.append({
            "severity": "high",
            "title": "Site accessible en HTTP (non chiffre)",
            "detail": "La connexion n'utilise pas HTTPS. Recommandation : installer un certificat SSL/TLS et forcer HTTPS.",
        })
        return findings

    try:
        import socket
        import datetime
        hostname = target.replace("https://", "").split("/")[0].split(":")[0]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=10),
            server_hostname=hostname,
        ) as sock:
            cert = sock.getpeercert()
            not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_remaining = (not_after - datetime.datetime.utcnow()).days

            if days_remaining < 0:
                findings.append({
                    "severity": "critical",
                    "title": "Certificat SSL expire",
                    "detail": f"Le certificat a expire il y a {abs(days_remaining)} jours.",
                })
            elif days_remaining < 30:
                findings.append({
                    "severity": "high",
                    "title": f"Certificat SSL expire dans {days_remaining} jours",
                    "detail": "Recommandation : renouveler le certificat rapidement.",
                })
            else:
                findings.append({
                    "severity": "info",
                    "title": f"Certificat SSL valide ({days_remaining} jours restants)",
                    "detail": f"Expiration : {not_after.strftime('%d/%m/%Y')}.",
                })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "severity": "critical",
            "title": "Certificat SSL invalide",
            "detail": f"Le certificat n'est pas de confiance : {str(e)}",
        })
    except Exception:
        pass

    return findings


def run_sqlmap(target):
    findings = []

    try:
        result = subprocess.run(
            [
                "sqlmap", "-u", target,
                "--batch", "--level=1", "--risk=1",
                "--threads=3", "--timeout=30",
                "--output-dir=/tmp/sqlmap_output",
                "--flush-session",
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        output = result.stdout

        if "is vulnerable" in output or "injectable" in output.lower():
            vuln_params = re.findall(r"Parameter: (\S+)", output)
            for param in vuln_params:
                findings.append({
                    "severity": "critical",
                    "title": f"Injection SQL detectee sur le parametre '{param}'",
                    "detail": f"Le parametre '{param}' est vulnerable a une injection SQL. "
                              f"Recommandation : utiliser des requetes parametrees (prepared statements).",
                })
        elif "all tested parameters do not appear to be injectable" in output:
            findings.append({
                "severity": "info",
                "title": "Aucune injection SQL detectee",
                "detail": "Les parametres testes ne semblent pas vulnerables aux injections SQL.",
            })
        else:
            findings.append({
                "severity": "info",
                "title": "Test SQLmap execute",
                "detail": "Aucune vulnerabilite SQL evidente detectee sur la cible.",
            })

    except subprocess.TimeoutExpired:
        findings.append({
            "severity": "warning",
            "title": "SQLmap : timeout",
            "detail": "Le test d'injection SQL a depasse le delai de 180 secondes.",
        })
    except FileNotFoundError:
        findings.append({
            "severity": "error",
            "title": "SQLmap non installe",
            "detail": "L'outil sqlmap n'est pas trouve. Installez-le avec : sudo apt install sqlmap",
        })
    except Exception as e:
        findings.append({
            "severity": "error",
            "title": "Erreur SQLmap",
            "detail": str(e),
        })

    return findings
