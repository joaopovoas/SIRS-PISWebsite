from flask import Flask, render_template, request, make_response, redirect, url_for
from flask import Blueprint
from argon2 import PasswordHasher
from flask_login import login_user, login_required, logout_user
from .models import User
from . import db, get_user_role
from .messages import login_msgs, register_msgs
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

import random
import string
import hashlib
auth = Blueprint('auth', __name__)
ph = PasswordHasher()


def verify_register(email, password, card_number, ccv, expiration):
    characters = string.ascii_letters + string.digits + string.punctuation
    salt = ''.join(random.choice(characters) for i in range(50))

    card_info = {"card_number": card_number, "ccv": ccv, "expiration": expiration}
    card_info = json.dumps(card_info)

    key_hash = hashlib.sha256()
    key_hash.update(bytes(password + salt[:25], 'utf8'))
    key_hash = key_hash.digest()

    iv_hash = hashlib.sha256()
    iv_hash.update(bytes(password + salt[25:], 'utf8'))
    iv_hash = hashlib.md5(iv_hash.digest()).digest()


    cipher = Cipher(algorithms.AES(key_hash), modes.CFB(iv_hash))

    encryptor = cipher.encryptor()
 

    encrypted_card_info = base64.b64encode(encryptor.update(card_info.encode()) + encryptor.finalize())

    user = User.query.filter_by(email=email).first()
    

    if user:
        return False
    else:
        hashed_password = ph.hash(password)
        new_user = User(email=email, password = hashed_password, cardinfo =encrypted_card_info, infosalt=salt, role = "default")
        db.session.add(new_user)
        db.session.commit()
        
        return True


@auth.route('/register')
def register():
    return render_template('register.html', role = get_user_role())


@auth.route('/register', methods = ['POST'])
def register_post():
    email, password = request.form.get("email"), request.form.get("password")
    card_number, ccv, expiration = request.form.get("card_number"), request.form.get("ccv"), request.form.get("expiration"),
    if not verify_register(email, password, card_number, ccv, expiration):
        return render_template("register.html", msg = register_msgs["error"], role = get_user_role(), msg_type = "error")
    else:
        return render_template("register.html", msg = register_msgs["success"], role = get_user_role(), msg_type = "success")


@auth.route('/login')
def login():
    return render_template("login.html", role = get_user_role())


@auth.route('/login', methods = ['POST'])
def login_post():
    email, password = request.form.get("email"), request.form.get("password")
    user = User.query.filter_by(email=email).first()
    msg = login_msgs["error"]

    if not user:
        msg = login_msgs["wrong password"] 
        return render_template("login.html", msg = msg, msg_type = "error", role = get_user_role())

    try:
        ph.verify(user.password, password)
        login_user(user, remember=False)

        return redirect(url_for('main.profile'))
    except:
        msg = login_msgs["wrong password"] 
        return render_template("login.html", msg = msg, msg_type = "error", role = get_user_role())

    


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.landing'))