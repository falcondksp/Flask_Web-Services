from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
import jwt
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123456@localhost/contoh'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'sangatrahasia'
db = SQLAlchemy(app)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token Is Missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            if not data['group']:
                return jsonify({'message': 'Sorry you are not admin!!'})
        except:
            return ({'message' : 'Token Is In Valid!!'})

        return f(*args, **kwargs)
    return decorated