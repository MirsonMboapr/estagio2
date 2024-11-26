import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bootstrap import Bootstrap

# Inicializar as extensões
db = SQLAlchemy()
lm = LoginManager()
bootstrap = Bootstrap()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'top-secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Inicializar as extensões
    db.init_app(app)
    lm.init_app(app)
    bootstrap.init_app(app)

    # Importar rotas
    from . import routes
    app.register_blueprint(routes.bp)

    return app
