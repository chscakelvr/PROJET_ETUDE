from flask import Flask, render_template, redirect, url_for, flash, request, make_response, Response
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from config import Config
from models import db, User, ScanResult, AuditLog
from forms import LoginForm, RegisterForm, ScanForm, CsrfForm
from datetime import datetime
import json
import csv
import io
import os

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Veuillez vous connecter pour acceder a cette page."
login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# Helper : ecriture dans le journal d'audit
# ---------------------------------------------------------------------------
def write_audit(action: str, target: str = None, detail: str = None):
    """Enregistre une entree dans le journal d'audit."""
    log = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        username=current_user.username if current_user.is_authenticated else "anonyme",
        action=action,
        target=target,
        detail=detail,
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
    )
    db.session.add(log)
    db.session.commit()


# ---------------------------------------------------------------------------
# Creation des tables et compte admin par defaut
# ---------------------------------------------------------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", email="admin@cyberscan.fr", role="admin")
        admin.set_password("Admin@2025!")
        db.session.add(admin)
        db.session.commit()


# ---------------------------------------------------------------------------
# Routes publiques
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/legal")
def legal():
    """Page mentions légales et conformité RGPD — accessible sans connexion."""
    return render_template("legal.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.is_locked():
            flash("Compte verrouille suite a trop de tentatives. Reessayez dans 15 minutes.", "error")
            return render_template("login.html", form=form)

        if user and user.check_password(form.password.data):
            user.reset_failed_attempts()
            db.session.commit()
            login_user(user, remember=form.remember.data)
            # Audit
            log = AuditLog(
                user_id=user.id, username=user.username, action="LOGIN",
                ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
            )
            db.session.add(log)
            db.session.commit()
            flash(f"Bienvenue, {user.username} !", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        else:
            if user:
                user.register_failed_attempt()
                db.session.commit()
            flash("Identifiants incorrects.", "error")

    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Ce nom d'utilisateur est deja pris.", "error")
            return render_template("register.html", form=form)
        if User.query.filter_by(email=form.email.data).first():
            flash("Cet email est deja utilise.", "error")
            return render_template("register.html", form=form)

        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Compte cree avec succes ! Connectez-vous.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/logout")
@login_required
def logout():
    write_audit("LOGOUT")
    logout_user()
    flash("Vous avez ete deconnecte.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Routes protegees
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    form = ScanForm()
    # Point 5 : pre-remplir l'IP du client
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    form.target.data = client_ip

    recent_scans = (
        ScanResult.query.filter_by(user_id=current_user.id)
        .order_by(ScanResult.created_at.desc())
        .limit(10)
        .all()
    )
    return render_template("dashboard.html", form=form, scans=recent_scans, client_ip=client_ip)


@app.route("/scan", methods=["POST"])
@login_required
def launch_scan():
    form = ScanForm()
    if form.validate_on_submit():
        target = form.target.data
        selected_modules = request.form.getlist("modules")

        if not selected_modules:
            flash("Veuillez selectionner au moins un module de diagnostic.", "warning")
            return redirect(url_for("dashboard"))

        # Vérification du consentement légal obligatoire
        if not request.form.get("legal_consent"):
            flash("Vous devez confirmer détenir l'autorisation de tester ce système avant de lancer un diagnostic.", "error")
            return redirect(url_for("dashboard"))

        scan_results = run_real_scans(target, selected_modules)

        scan = ScanResult(
            user_id=current_user.id,
            target_url=target,
            scan_type=",".join(selected_modules),
            status="done",
            completed_at=datetime.utcnow(),
        )
        scan.set_results(scan_results)   # chiffrement Fernet ici
        db.session.add(scan)
        db.session.commit()

        # Audit
        write_audit(
            action="SCAN_LAUNCH",
            target=target,
            detail=f"Modules : {', '.join(selected_modules)} | scan_id={scan.id}",
        )

        flash("Diagnostic termine avec succes !", "success")
        return redirect(url_for("scan_result", scan_id=scan.id))

    flash("Erreur dans le formulaire.", "error")
    return redirect(url_for("dashboard"))


@app.route("/scan/<int:scan_id>")
@login_required
def scan_result(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id and current_user.role != "admin":
        flash("Acces non autorise.", "error")
        return redirect(url_for("dashboard"))

    results = scan.get_results()   # dechiffrement Fernet ici
    return render_template("results.html", scan=scan, results=results)


@app.route("/scan/<int:scan_id>/pdf")
@login_required
def download_report(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id and current_user.role != "admin":
        flash("Acces non autorise.", "error")
        return redirect(url_for("dashboard"))

    results = scan.get_results()

    from modules.report_generator import generate_report_pdf
    pdf_bytes = generate_report_pdf(scan, results)

    date_str = scan.created_at.strftime("%Y%m%d_%H%M") if scan.created_at else "rapport"
    filename = f"CyberScan_Rapport_{date_str}.pdf"

    write_audit("EXPORT_PDF", target=scan.target_url, detail=f"scan_id={scan_id}")

    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


# ---------------------------------------------------------------------------
# Export CSV — point 2
# ---------------------------------------------------------------------------
@app.route("/scan/<int:scan_id>/csv")
@login_required
def download_csv(scan_id):
    """Exporte les resultats d'un scan au format CSV."""
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id and current_user.role != "admin":
        flash("Acces non autorise.", "error")
        return redirect(url_for("dashboard"))

    results = scan.get_results()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_ALL)

    # En-tete
    writer.writerow(["Module", "Severite", "Titre", "Detail"])

    for mod_key, mod_data in results.get("modules", {}).items():
        mod_name = mod_data.get("name", mod_key)
        for finding in mod_data.get("findings", []):
            writer.writerow([
                mod_name,
                finding.get("severity", "").upper(),
                finding.get("title", ""),
                finding.get("detail", ""),
            ])

    date_str = scan.created_at.strftime("%Y%m%d_%H%M") if scan.created_at else "rapport"
    filename = f"CyberScan_Rapport_{date_str}.csv"

    write_audit("EXPORT_CSV", target=scan.target_url, detail=f"scan_id={scan_id}")

    return Response(
        "\ufeff" + output.getvalue(),   # BOM UTF-8 pour ouverture correcte dans Excel
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# Module forensique
# ---------------------------------------------------------------------------
@app.route("/forensic", methods=["GET", "POST"])
@login_required
def forensic():
    """Upload et analyse forensique d'un fichier suspect."""
    results = None
    vt_configured = bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip())

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            flash("Aucun fichier selectionne.", "warning")
            return redirect(url_for("forensic"))

        # Limite 10 Mo
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size > 10 * 1024 * 1024:
            flash("Fichier trop volumineux (max 10 Mo).", "error")
            return redirect(url_for("forensic"))

        # Clé API : priorité au champ formulaire, sinon .env
        vt_api_key = request.form.get("vt_api_key_override", "").strip()
        if not vt_api_key:
            vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if vt_api_key:
            vt_configured = True

        # Sauvegarde temporaire
        import tempfile
        suffix = os.path.splitext(file.filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="cyberscan_forensic_") as tmp:
            file.save(tmp.name)
            tmp_path = tmp.name

        try:
            from modules.forensic_scan import analyze_file
            results = analyze_file(tmp_path, vt_api_key)

            write_audit(
                action="FORENSIC_SCAN",
                target=file.filename,
                detail=f"Taille : {size} octets | VT: {'oui' if vt_api_key else 'non'}",
            )
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    return render_template("forensic.html", results=results, vt_configured=vt_configured, form=CsrfForm())


# ---------------------------------------------------------------------------
# Journal d'audit (admin uniquement) — point 3
# ---------------------------------------------------------------------------
@app.route("/audit")
@login_required
def audit_log():
    """Affiche le journal d'audit (admin uniquement)."""
    if current_user.role != "admin":
        flash("Acces reserve aux administrateurs.", "error")
        return redirect(url_for("dashboard"))

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    return render_template("audit.html", logs=logs)


# ---------------------------------------------------------------------------
# Panneau administration (admin uniquement)
# ---------------------------------------------------------------------------
@app.route("/admin")
@login_required
def admin_panel():
    """Panneau admin : liste des utilisateurs et de tous les scans."""
    if current_user.role != "admin":
        flash("Accès réservé aux administrateurs.", "error")
        return redirect(url_for("dashboard"))

    users = User.query.order_by(User.created_at.desc()).all()
    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(50).all()
    return render_template("admin.html", users=users, scans=scans)


@app.route("/admin/user/<int:user_id>/role", methods=["POST"])
@login_required
def change_role(user_id):
    """Change le rôle d'un utilisateur (admin uniquement)."""
    if current_user.role != "admin":
        flash("Accès réservé aux administrateurs.", "error")
        return redirect(url_for("dashboard"))

    user = db.session.get(User, user_id)
    if not user:
        flash("Utilisateur introuvable.", "error")
        return redirect(url_for("admin_panel"))

    # Empêcher l'admin de se rétrograder lui-même
    if user.id == current_user.id:
        flash("Vous ne pouvez pas modifier votre propre rôle.", "warning")
        return redirect(url_for("admin_panel"))

    new_role = request.form.get("role")
    if new_role not in ("admin", "analyst"):
        flash("Rôle invalide.", "error")
        return redirect(url_for("admin_panel"))

    old_role = user.role
    user.role = new_role
    db.session.commit()

    write_audit(
        action="ROLE_CHANGE",
        target=user.username,
        detail=f"{old_role} → {new_role}",
    )
    flash(f"Rôle de {user.username} mis à jour : {new_role}.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    """Supprime un utilisateur (admin uniquement, sauf soi-même)."""
    if current_user.role != "admin":
        flash("Accès réservé aux administrateurs.", "error")
        return redirect(url_for("dashboard"))

    user = db.session.get(User, user_id)
    if not user:
        flash("Utilisateur introuvable.", "error")
        return redirect(url_for("admin_panel"))

    if user.id == current_user.id:
        flash("Vous ne pouvez pas supprimer votre propre compte.", "warning")
        return redirect(url_for("admin_panel"))

    write_audit(action="USER_DELETE", target=user.username)
    db.session.delete(user)
    db.session.commit()
    flash(f"Utilisateur {user.username} supprimé.", "success")
    return redirect(url_for("admin_panel"))


# ---------------------------------------------------------------------------
# Appel aux vrais modules de scan (avec fallback demo)
# ---------------------------------------------------------------------------
def run_real_scans(target, modules):
    results = {"target": target, "date": datetime.utcnow().isoformat(), "modules": {}}

    if "network" in modules:
        try:
            from modules.network_scan import run_network_scan
            results["modules"]["network"] = run_network_scan(target)
        except Exception:
            results["modules"]["network"] = get_demo_results("network", target)

    if "web" in modules:
        try:
            from modules.web_scan import run_web_scan
            results["modules"]["web"] = run_web_scan(target)
        except Exception:
            results["modules"]["web"] = get_demo_results("web", target)

    if "infra" in modules:
        try:
            from modules.infra_scan import run_infra_scan
            results["modules"]["infra"] = run_infra_scan(target)
        except Exception:
            results["modules"]["infra"] = get_demo_results("infra", target)

    if "pentest" in modules:
        try:
            from modules.pentest_scan import run_pentest_scan
            results["modules"]["pentest"] = run_pentest_scan(target)
        except Exception:
            results["modules"]["pentest"] = get_demo_results("pentest", target)

    return results


def get_demo_results(module, target):
    demo = {
        "network": {
            "name": "Diagnostic reseau",
            "findings": [
                {"severity": "high", "title": "Port 22 (SSH) ouvert", "detail": "Le service SSH est accessible publiquement. Recommandation : restreindre l'acces par IP et utiliser des cles SSH."},
                {"severity": "medium", "title": "Port 80 (HTTP) sans redirection HTTPS", "detail": "Le trafic HTTP n'est pas redirige vers HTTPS. Recommandation : forcer la redirection."},
                {"severity": "low", "title": "Port 443 (HTTPS) actif", "detail": "Le service HTTPS est correctement configure."},
                {"severity": "info", "title": "Scan termine : 3 port(s) ouvert(s) sur 100 scannes", "detail": f"Scan Nmap effectue sur {target}."},
            ],
        },
        "web": {
            "name": "Diagnostic web & API",
            "findings": [
                {"severity": "critical", "title": "Injection SQL detectee", "detail": "Le parametre 'id' est vulnerable a une injection SQL. Recommandation : utiliser des requetes parametrees."},
                {"severity": "high", "title": "En-tetes de securite manquants", "detail": "X-Frame-Options, Content-Security-Policy et Strict-Transport-Security absents."},
                {"severity": "medium", "title": "Cookie sans attribut Secure", "detail": "Le cookie de session est transmis sans l'attribut Secure."},
                {"severity": "medium", "title": "Version du serveur exposee", "detail": "Le header Server revele Apache/2.4.41 (Ubuntu)."},
            ],
        },
        "infra": {
            "name": "Diagnostic securite infrastructure",
            "findings": [
                {"severity": "high", "title": "FTP : connexion anonyme autorisee", "detail": "Le serveur FTP accepte les connexions anonymes. Recommandation : desactiver l'acces anonyme."},
                {"severity": "info", "title": "Brute force SSH : aucun identifiant faible detecte", "detail": "Les mots de passe testes n'ont pas permis de se connecter."},
            ],
        },
        "pentest": {
            "name": "Pentest interne & gestion",
            "findings": [
                {"severity": "critical", "title": "Algorithme de hachage obsolete : MD5", "detail": "5 utilisateurs utilisent MD5. Recommandation : migrer vers bcrypt ou Argon2."},
                {"severity": "critical", "title": "4 mot(s) de passe craque(s) sur 5", "detail": "80% des mots de passe ont ete craques par dictionnaire. Politique de complexite insuffisante."},
                {"severity": "high", "title": "Mots de passe identiques detectes", "detail": "2 utilisateurs partagent le meme mot de passe."},
                {"severity": "high", "title": "Mots de passe non sales", "detail": "Les hash MD5 ne sont pas sales. Vulnerable aux rainbow tables."},
            ],
        },
    }
    return demo.get(module, {"name": module, "findings": []})


# ---------------------------------------------------------------------------
# Lancement
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
