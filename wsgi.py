"""
Point d'entree WSGI pour CyberScan.

Ce fichier expose la variable 'application' utilisee par les serveurs WSGI
(Gunicorn, uWSGI, mod_wsgi...) pour servir l'application Flask en production.
"""
import sys
import os

project_dir = os.path.dirname(os.path.abspath(__file__))
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

from app import app as application
