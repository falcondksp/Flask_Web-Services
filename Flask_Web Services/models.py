from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from setting import app, db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(150), unique=True)
    name = db.Column(db.String(150))
    password = db.Column(db.String(180))
    admin = db.Column(db.Boolean)