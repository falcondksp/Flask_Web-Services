from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from models import User, app, db
from setting import token_required
import jwt
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import datetime





@app.route('/user', methods=['GET'])
@token_required
def get_all_users():

    user = User.query.all()
    output = []

    for user in user:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data= {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user():

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New User Created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def update(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No User Found!'})

    user.admin = True
    db.session.commit()

    return  jsonify({'message' : 'The User Has Ben Promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(public_id):

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({'message' : 'No User Found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The User has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login Required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login Required!"'})

    if check_password_hash(user.password, auth.password) :
        token = jwt.encode({'public_id' : user.public_id,'group' : user.admin, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token' : token})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login Required!"'})