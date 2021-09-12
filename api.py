from flask import Flask, request, jsonify, make_response, render_template, session, redirect
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import sqlite3

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'

db = SQLAlchemy(app)
print(db)

# login_manager = LoginManager()
# login_manager.init_app(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_users_list(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'You are not permitted! Only admin can update!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'Status' : '200','Message': 'All Users Data Fetched Successfully!', 'Users' : output})

@app.route('/user/<id>', methods=['GET'])
@token_required
def get_user_profile(current_user, id):

    if not current_user.admin:
        return jsonify({'message' : 'You are not permitted! Only admin can update!'})

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'Message' : 'No user found!'})

    user_data = {}
    user_data['id'] = user.id
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['public_id'] = user.public_id
    user_data['admin'] = user.admin

    return jsonify({'Status' : '200','Message': 'User Details Fetched Successfully!', 'user' : user_data})

@app.route('/user/add_user', methods=['POST'])
def create_user():
    data = request.get_json()
    #
    user = User.query.filter_by(email=data['email']).first()
    if user:
        return jsonify({'Message' : 'User already exists!'})
    else:
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(public_id=str(uuid.uuid4()), name=data['name'], email=data['email'], password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'Status' : '201', 'Message' : 'User created successfully!'})

@app.route('/user/<id>', methods=['PUT'])
@token_required
def admin_user(current_user, id):
    if not current_user.admin:
        return jsonify({'Message' : 'You are not permitted! Only admin can update!'})

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'Message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'Message' : 'The user has been promoted as admin!'})

@app.route('/user/<id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    if not current_user.admin:
        return jsonify({'Message' : 'You are not permitted! Only admin can update!'})

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'Message' : 'User not found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'Message' : 'The user has been deleted!'})

@app.route('/user/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@app.route('/')
def index():
    print('hello')
    return render_template('index.html')

@app.route('/signin')
def signin():
    print('signin')
    return render_template('signin.html')

@app.route('/')
def signin_form():
    print('signin_form')
    return render_template('/')

@app.route('/signup')
def signup():
    return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)