from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import re


class LoginForm(FlaskForm):
    username = StringField(
        "Nom d'utilisateur",
        validators=[DataRequired(message="Ce champ est requis.")],
    )
    password = PasswordField(
        "Mot de passe",
        validators=[DataRequired(message="Ce champ est requis.")],
    )
    remember = BooleanField("Se souvenir de moi")
    submit = SubmitField("Se connecter")


class RegisterForm(FlaskForm):
    username = StringField(
        "Nom d'utilisateur",
        validators=[
            DataRequired(),
            Length(min=3, max=80, message="Entre 3 et 80 caracteres."),
        ],
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(message="Adresse email invalide.")],
    )
    password = PasswordField(
        "Mot de passe",
        validators=[
            DataRequired(),
            Length(min=8, message="Minimum 8 caracteres."),
        ],
    )
    password_confirm = PasswordField(
        "Confirmer le mot de passe",
        validators=[
            DataRequired(),
            EqualTo("password", message="Les mots de passe ne correspondent pas."),
        ],
    )
    submit = SubmitField("Creer le compte")

    def validate_password(self, field):
        password = field.data
        if not re.search(r"[A-Z]", password):
            raise ValidationError("Au moins une majuscule requise.")
        if not re.search(r"[a-z]", password):
            raise ValidationError("Au moins une minuscule requise.")
        if not re.search(r"[0-9]", password):
            raise ValidationError("Au moins un chiffre requis.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValidationError("Au moins un caractere special requis.")


class ScanForm(FlaskForm):
    target = StringField(
        "URL ou adresse IP cible",
        validators=[DataRequired(message="Veuillez saisir une cible.")],
    )
    modules = SelectMultipleField(
        "Modules de diagnostic",
        choices=[
            ("network", "Diagnostic reseau"),
            ("web", "Diagnostic web & API"),
            ("infra", "Diagnostic securite infrastructure"),
            ("pentest", "Pentest interne & gestion"),
        ],
    )
    submit = SubmitField("Lancer le diagnostic")


class CsrfForm(FlaskForm):
    """Formulaire vide utilisé uniquement pour la protection CSRF dans les templates sans form WTF."""
    pass
