"""
Point d'entree WSGI pour AlwaysData.
AlwaysData cherche une variable 'application' dans ce fichier.
"""
import sys
import os

project_dir = os.path.dirname(os.path.abspath(__file__))
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

from app import app as application
