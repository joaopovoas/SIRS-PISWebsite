from locale import currency
from flask import Blueprint
from flask import Flask, render_template, request, make_response, send_from_directory, redirect, url_for
from flask_login import login_required, current_user
from functools import wraps
from . import admin_login_required, db, get_user_role
from .models import Transaction

main = Blueprint('main', __name__)
app = Flask(__name__)


@app.route("/static/<path:path>")
def static_dir(path):
    return send_from_directory("static", path)


@main.route('/')
def landing():
    return render_template("index.html", role=get_user_role())


@main.route('/profile')
@login_required
def profile():
    return render_template('account.html', role=get_user_role(), username=current_user.email)


@main.route('/transactions')
@login_required
def history():
    transactions = ''

    if get_user_role() == 'admin':
        transactions = Transaction.query.all()
    else:
        transactions = Transaction.query.filter_by(
            paidbyemail=current_user.email)

    return render_template('transactions.html', catalog=transactions, role=get_user_role())


@main.route('/admin')
@login_required
@admin_login_required
def admin():
    return render_template('account.html', role=get_user_role())


@main.route('/transaction/<id>')
def transaction(id):
    transaction = Transaction.query.filter_by(transactionID=id).first()

    if not transaction:
        redirect(url_for('main.landing'))

    return render_template('transaction.html', role=get_user_role(), price=transaction.price, transactionID=transaction.transactionID, currency=transaction.currency)
