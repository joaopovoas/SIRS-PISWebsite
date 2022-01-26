from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from flask_login import UserMixin
from . import db
    

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(97), nullable=False)
    cardinfo = db.Column(db.String(600), nullable=False)
    infosalt = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(50), default = "standard", nullable=False)

class Transaction(db.Model):
    __tablename__ = 'transaction'
    id = db.Column(db.Integer, primary_key=True)
    transactionID = db.Column(db.String(97), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(97), nullable=False)
    bank = db.Column(db.String(97), nullable=False)
    paidbyemail = db.Column(db.String(100), default="UNPAID", nullable=False)



class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float(), nullable=False)
    type = db.Column(db.String(100), nullable=False)




def init(app):
    with app.app_context():
        db.create_all()