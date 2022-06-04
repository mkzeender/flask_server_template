from . import db
from .models import User

from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = bool(request.form.get('remember'))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash('Wrong email lol')
        return redirect(url_for('auth.login'))

    if not check_password_hash(user.password, password):
        flash('Wrong password lol')

        return redirect(url_for('auth.login'))

    return redirect(url_for('main.profile'))


@auth.route('/signup')
def signup():
    return render_template('signup.html')


@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    if User.query.filter_by(email=email).first():  # user exists
        flash('User already exists')
        return redirect(url_for('auth.signup'))

    user = User(email=email, name=name, password=generate_password_hash(password))

    db.session.add(user)
    db.session.commit()

    return redirect(url_for('auth.login'))


@auth.route('/logout')
def logout():
    return redirect(url_for('main.index'))
