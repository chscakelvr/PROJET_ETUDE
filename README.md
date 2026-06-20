# CyberScan — Toolbox de diagnostic de vulnérabilités

> Détecter aujourd'hui. Protéger demain.

## Présentation

CyberScan est une toolbox web de diagnostic de vulnérabilités développée dans le cadre du projet d'études Mastère Cybersécurité — Sup de Vinci (2025-2026).

## Structure du projet

```
cyberscan/
├── app.py                  # Application Flask principale
├── config.py               # Configuration
├── models.py               # Modèles BDD (User, ScanResult)
├── forms.py                # Formulaires Flask-WTF
├── wsgi.py                 # Point d'entrée pour AlwaysData
├── requirements.txt        # Dépendances Python
├── .env.example            # Variables d'environnement (exemple)
├── .gitignore
├── static/
│   └── css/
│       └── style.css       # Feuille de style (thème corporate light)
├── templates/
│   ├── base.html           # Layout commun
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html      # Tableau de bord + 4 modules
│   └── results.html        # Résultats + bouton PDF
└── modules/
    ├── __init__.py
    ├── network_scan.py     # Nmap
    ├── web_scan.py         # SQLmap + en-têtes HTTP
    ├── infra_scan.py       # Hydra (brute force SSH/FTP)
    ├── pentest_scan.py     # John the Ripper
    └── report_generator.py # Génération PDF (ReportLab)
```

## Installation locale (Windows)

```powershell
# 1. Cloner le dépôt
git clone https://github.com/VOTRE_REPO/cyberscan.git
cd cyberscan

# 2. Créer l'environnement virtuel
python -m venv venv
venv\Scripts\activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Copier le fichier .env
copy .env.example .env

# 5. Lancer l'application
python app.py
```

Accédez à `http://localhost:5000`

## Compte par défaut

| Utilisateur | Mot de passe  |
|-------------|---------------|
| admin       | Admin@2025!   |

## Fonctionnement

### En local (Kali Linux avec outils installés)
Les modules utilisent les vrais outils (Nmap, SQLmap, Hydra, John the Ripper) pour les scans.

### Sur AlwaysData (hébergement mutualisé)
Les outils de scan ne peuvent pas tourner. L'application bascule automatiquement
sur des résultats de démonstration réalistes. L'interface et le rapport PDF restent
identiques.

## Déploiement sur AlwaysData

1. Pousser le code sur GitHub
2. Dans AlwaysData : Sites → Modifier votre site
3. Type : Python WSGI
4. Chemin WSGI : `wsgi.py`
5. Répertoire de travail : `/home/VOTRE_COMPTE/cyberscan/`
6. Se connecter en SSH et installer : `pip install -r requirements.txt`
7. Configurer `.env` avec une vraie clé secrète
8. Redémarrer le site

## Équipe

- **Alexandre Morin** — Architecte / Développeur back-end
- **Sofia Benali** — Analyste Sécurité / QA
- **Thomas Leclerc** — Interface & Reporting
