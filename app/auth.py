from flask import Blueprint, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from .forms import RegisterForm, LoginForm
from .db import add_user, get_user

auth_routes = Blueprint('auth', __name__, url_prefix='/auth')

@auth_routes.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing = get_user(form.username.data)
        if existing:
            flash("Username already exists.")
            return redirect(url_for('auth.register'))
        hashed_pw = generate_password_hash(form.password.data)
        add_user(form.username.data, hashed_pw)
        flash("Registered successfully.")
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@auth_routes.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = get_user(form.username.data)
        if user and check_password_hash(user[2], form.password.data):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('main.home'))
        flash("Invalid credentials.")
    return render_template('auth/login.html', form=form)

@auth_routes.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
