from flask import Flask, render_template, request, redirect, url_for, flash, \
    Response, session, Blueprint, send_file, make_response, jsonify
from flask_bootstrap import Bootstrap
from filters import datetimeformat, file_type, file_size
from flask_login import login_required, current_user
# from . import db
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)
Bootstrap(app)
app.secret_key = 'secret-key'
app.jinja_env.filters['datetimeformat'] = datetimeformat
app.jinja_env.filters['file_type'] = file_type
app.jinja_env.filters['file_size'] = file_size

db = SQLAlchemy()

@app.route('/')
def index():
    return render_template('home/index.html') 

@app.route('/about')
def about():
    return render_template('home/about.html')

@app.route('/contact')
def contact():
    return render_template('home/contact.html')


def create_app():

    app.config['SECRET_KEY'] = 'secret-key-goes-here'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://<username>:<password>@localhost/updatabox'
    SQLALCHEMY_ENGINE_OPTIONS = {
    "max_overflow": 15,
    "pool_pre_ping": True,
    "pool_recycle": 60 * 60,
    "pool_size": 30,
    }
    db.init_app(app)

    from auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    app_blueprint = Blueprint('app', __name__)
    app.register_blueprint(app_blueprint)
    return app

def run_app():
    app.config['SECRET_KEY'] = 'secret-key-goes-here'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://<username>:<password>@localhost/updatabox'
    SQLALCHEMY_ENGINE_OPTIONS = {
    "max_overflow": 15,
    "pool_pre_ping": True,
    "pool_recycle": 60 * 60,
    "pool_size": 30,
    }
    db.init_app(app)

    from auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        return User.query.get(int(user_id))
    app.run(debug=True)

if __name__ == "__main__":
    run_app()
