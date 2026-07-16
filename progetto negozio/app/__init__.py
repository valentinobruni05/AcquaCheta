import os
import re
import secrets
from flask import Flask
from dotenv import load_dotenv
from app.extensions import db, login_manager, limiter, csrf
from app.blueprint.routes import bp as routes
from app.blueprint.auth import bp as auth
from datetime import timedelta

# Carica variabili .env
load_dotenv()


def create_app():
    app = Flask(__name__, static_folder='../static')

    # SECRET KEY
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # -------------------------------------------------
    # Configurazione database TiDB Cloud
    # -------------------------------------------------
    db_user = os.environ.get('DB_USER')
    db_pass = os.environ.get('DB_PASS')
    db_host = os.environ.get('DB_HOST')
    db_port = os.environ.get('DB_PORT', '4000')
    db_name = os.environ.get('DB_NAME')
    db_ssl_ca = os.environ.get('DB_SSL_CA')

    # Controllo nome database
    if not re.match(r'^[a-zA-Z0-9_]+$', db_name):
        raise ValueError(f"Nome database non valido: {db_name}")

    # Connessione SQLAlchemy a TiDB
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"mysql+pymysql://{db_user}:{db_pass}"
        f"@{db_host}:{db_port}/{db_name}"
        f"?ssl_ca={db_ssl_ca}&ssl_verify_cert=true"
    )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Sessione
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

    # Cookie sicurezza
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'

    # Upload massimo
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


    # -------------------------------------------------
    # Inizializzazione estensioni
    # -------------------------------------------------
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)


    # Security headers
    from flask_talisman import Talisman

    Talisman(
        app,
        force_https=False,
        session_cookie_secure=False,
        content_security_policy={
            'default-src': ["'self'"],
            'script-src': ["'self'", 'cdn.jsdelivr.net'],
            'style-src': ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'fonts.googleapis.com'],
            'img-src': ["'self'", 'data:'],
            'font-src': ["'self'", 'cdn.jsdelivr.net', 'fonts.gstatic.com'],
        },
        x_content_type_options=True,
        frame_options='DENY',
        referrer_policy='strict-origin-when-cross-origin',
    )


    # Blueprint
    app.register_blueprint(routes)
    app.register_blueprint(auth)


    # Crea tabelle
    with app.app_context():
        try:
            db.create_all()
            print("Database collegato e tabelle create correttamente")
        except Exception as e:
            print(f"Errore database: {e}")


    return app
