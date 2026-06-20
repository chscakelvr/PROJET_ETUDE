from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import json

db = SQLAlchemy()

# ---------------------------------------------------------------------------
# Chiffrement Fernet des resultats de scan
# ---------------------------------------------------------------------------
def _get_fernet():
    """Retourne une instance Fernet basee sur la cle dans l'env."""
    from cryptography.fernet import Fernet
    key = os.environ.get("FERNET_KEY")
    if not key:
        # Genere une cle et l'affiche une fois (dev uniquement)
        key = Fernet.generate_key().decode()
        print(f"[CyberScan] ATTENTION : aucune FERNET_KEY definie. Cle generee (a copier dans .env) : {key}")
        os.environ["FERNET_KEY"] = key
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_json(data: dict) -> str:
    """Chiffre un dict Python en JSON puis en bytes Fernet, renvoie une str base64."""
    f = _get_fernet()
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return f.encrypt(raw).decode("utf-8")


def decrypt_json(token: str) -> dict:
    """Dechiffre un token Fernet et renvoie le dict original."""
    if not token:
        return {}
    f = _get_fernet()
    try:
        raw = f.decrypt(token.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        # Compatibilite : si la valeur est du JSON brut non chiffre (anciens enregistrements)
        try:
            return json.loads(token)
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Modeles
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    """Modele utilisateur avec authentification securisee."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="analyst")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def register_failed_attempt(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)

    def reset_failed_attempts(self):
        self.failed_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()

    def __repr__(self):
        return f"<User {self.username}>"


class ScanResult(db.Model):
    """Stocke les resultats des scans — resultats chiffres avec Fernet."""

    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default="pending")
    # Stockage chiffre (Fernet) — utiliser les proprietes set_results / get_results
    results_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    user = db.relationship("User", backref=db.backref("scans", lazy=True))

    def set_results(self, data: dict):
        """Chiffre et stocke les resultats."""
        self.results_json = encrypt_json(data)

    def get_results(self) -> dict:
        """Dechiffre et retourne les resultats."""
        return decrypt_json(self.results_json)

    def __repr__(self):
        return f"<Scan {self.target_url} - {self.status}>"


class AuditLog(db.Model):
    """Journal d'audit : trace toutes les actions sensibles."""

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(80))          # denormalise pour lisibilite
    action = db.Column(db.String(100), nullable=False)   # ex: LOGIN, SCAN_LAUNCH, EXPORT_CSV
    target = db.Column(db.String(500))           # IP / URL ciblee, si pertinent
    detail = db.Column(db.Text)                  # infos supplementaires libres
    ip_address = db.Column(db.String(45))        # IPv4 ou IPv6

    user = db.relationship("User", backref=db.backref("audit_logs", lazy=True))

    def __repr__(self):
        return f"<AuditLog {self.action} by {self.username} at {self.timestamp}>"
