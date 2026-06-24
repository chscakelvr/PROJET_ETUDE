# CyberScan
> Détecter aujourd'hui. Protéger demain.

## Présentation
CyberScan est une toolbox web de diagnostic de vulnérabilités développée dans le cadre du projet d'études Mastère Cybersécurité.

L'application permet à un analyste pentest de lancer en quelques clics un ensemble de diagnostics automatisés (réseau, web, infrastructure, pentest interne, forensique) sur une cible donnée, puis de générer un rapport professionnel au format PDF ou CSV.

## Structure du projet
cyberscan/
├── app.py                  # Application Flask principale
├── config.py               # Configuration
├── models.py               # Modèles BDD (User, ScanResult, AuditLog)
├── forms.py                # Formulaires Flask-WTF
├── wsgi.py                 # Point d'entrée WSGI
├── requirements.txt        # Dépendances Python
├── .env.example            # Variables d'environnement (exemple)
├── .gitignore
├── static/
│   ├── css/
│   │   └── style.css       # Feuille de style
│   └── img/
│       ├── logo.png        # Logo CyberScan
│       └── cover_template.png  # Page de garde des rapports PDF
├── templates/
│   ├── base.html           # Layout commun
│   ├── login.html          # Page de connexion
│   ├── register.html       # Création de compte
│   ├── dashboard.html      # Tableau de bord + modules
│   ├── results.html        # Résultats + exports PDF/CSV
│   ├── forensic.html       # Module forensique VirusTotal
│   ├── admin.html          # Panneau d'administration
│   ├── audit.html          # Journal d'audit
│   └── legal.html          # Mentions légales & RGPD
└── modules/
    ├── __init__.py
    ├── network_scan.py     # Module réseau (Nmap)
    ├── web_scan.py         # Module web & API (SQLmap, HTTP)
    ├── infra_scan.py       # Module infrastructure (Hydra)
    ├── pentest_scan.py     # Module pentest interne (John the Ripper)
    ├── forensic_scan.py    # Module forensique (VirusTotal)
    └── report_generator.py # Génération des rapports PDF (ReportLab)
    
## Fonctionnalités principales
5 modules de diagnostic : réseau, web & API, infrastructure, pentest interne, forensique
Interface web simple et accessible, exploitable sans compétences avancées
Authentification sécurisée avec verrouillage anti-brute force
Contrôle d'accès par rôle (RBAC : analyst / admin)
Chiffrement Fernet (AES-128) des résultats de scan en base de données
Journal d'audit horodaté de toutes les actions sensibles
Génération de rapports PDF professionnels et exports CSV
Conformité RGPD avec page de mentions légales intégrée

## Installation locale
a. Sur Kali Linux (recommandé — les vrais outils d'audit sont disponibles)

# 1. Cloner le dépôt
git clone https://github.com/chscakelvr/PROJET_ETUDE.git
cd PROJET_ETUDE

# 2. Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Copier le fichier .env et le configurer
cp .env.example .env
# Générer une clé Fernet :
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Coller la clé dans .env à la ligne FERNET_KEY=
# Renseigner également SECRET_KEY et VIRUSTOTAL_API_KEY

# 5. Lancer l'application
flask run --host=0.0.0.0 --port=5000
Accédez à http://127.0.0.1:5000 (ou http://IP_DU_SERVEUR:5000 depuis une autre machine du réseau).

b. Sur Windows
git clone https://github.com/chscakelvr/PROJET_ETUDE.git
cd PROJET_ETUDE

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

copy .env.example .env
# Configurer .env (cf. instructions ci-dessus)

python app.py
Compte par défaut
Utilisateur	Mot de passe
admin	Admin@2025!

Environnement de test recommandé
Pour expérimenter la toolbox dans des conditions réalistes, nous recommandons un environnement VMware isolé comprenant :

a. Une VM Kali Linux hébergeant l'application et les outils d'audit
ou
b. Une VM Windows 10 simulant le poste analyste
Une VM Metasploitable 2 servant de cible volontairement vulnérable
L'ensemble communique sur un réseau virtuel interne (NAT) isolé, conformément aux recommandations de l'ANSSI pour les environnements de test.

## Cadre légal
Les outils intégrés à CyberScan (Nmap, SQLmap, Hydra, John the Ripper) ne peuvent être utilisés que sur des systèmes pour lesquels une autorisation écrite préalable a été obtenue, conformément aux articles 323-1 à 323-7 du Code pénal français. L'application intègre nativement une page de mentions légales et reproduit le consentement client sur chaque rapport généré.

## Équipe projet
Asmaa BAHAMMOU — Architecte & développeuse back-end
Astan DIANKA — Analyste sécurité, QA & forensique
Solène BERNABE — Développeur Interface & reporting

## Licence
Projet académique réalisé dans le cadre du Mastère 1 Cybersécurité de Sup de Vinci.
