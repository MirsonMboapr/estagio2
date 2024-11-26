from flask import Blueprint, render_template, redirect, url_for, flash, session, abort
from flask_login import login_user, current_user, logout_user
from app import db
from app.models import User
from app.forms import RegisterForm, LoginForm
import onetimepass
import pyqrcode
from io import BytesIO

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('main.register'))
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        session['username'] = user.username
        return redirect(url_for('main.two_factor_setup'))
    return render_template('register.html', form=form)

@bp.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('main.index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('main.index'))
    return render_template('two-factor-setup.html')

@bp.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)
    del session['username']
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            flash('Invalid username, password or token.')
            return redirect(url_for('main.login'))
        login_user(user)
        flash('You are now logged in!')
        return redirect(url_for('main.index'))
    return render_template('login.html', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))
