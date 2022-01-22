from flask import Blueprint
from flask import Flask, render_template, request, make_response
from flask_login import login_required, current_user
from functools import wraps
from . import admin_login_required, db, get_user_role
from .models import Item
from .messages import update_msgs

main = Blueprint('main', __name__)


@main.route('/')
def landing():
    return render_template("index.html", role = get_user_role())


@main.route('/profile')
@login_required
def profile():
    return render_template('account.html', role = get_user_role(), username = current_user.email)


@main.route('/create_item', methods = ['POST'])
@login_required
def create_item():
    name, description = request.form.get("name"), request.form.get("description")
    price,type = request.form.get("price"), request.form.get("type")

    if not (name and description and price):
        return render_template('create_item.html', error_msg = "all fields are mandatory")

    #filter inputs here
    new_item = Item(name = name, description = description, price = price, type = type)
    db.session.add(new_item)
    db.session.commit()
        
    return render_template('create_item.html', role = get_user_role())


@main.route('/marketplace')
def marketplace():
    items = Item.query.all()

    return render_template('marketplace.html', catalog = items, role = get_user_role())


@main.route('/marketplace/<id>')
def show_item(id):
    item = Item.query.filter_by(id=id).first()

    return render_template('view_item.html', item = item, role = get_user_role())



@main.route('/admin')
@login_required
@admin_login_required
def admin():
    return render_template('account.html', role = get_user_role())


@main.route('/create_item')
@login_required
@admin_login_required
def create_item_landing():
    return render_template('create_item.html', role = get_user_role())


@main.route('/edit_item/<id>')
@login_required
@admin_login_required
def edit_item(id):
    item = Item.query.filter_by(id=id).first()

    return render_template('edit_item.html', role = get_user_role(), item = item)


@main.route('/edit_item/<id>', methods = ["POST"])
@login_required
@admin_login_required
def edit_item_post(id):
    name, description = request.form.get("name"), request.form.get("description")
    price,type = request.form.get("price"), request.form.get("type")

    item = Item.query.filter_by(id=id).first()
    
    item.name = name
    item.description = description
    item.price = price
    item.type = type

    db.session.commit()

    return render_template('edit_item.html', role = get_user_role(), 
        msg = update_msgs["success"], msg_type = 'success', item = item)