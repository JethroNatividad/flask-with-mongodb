from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from bcrypt import hashpw, checkpw, gensalt
from mongoflask import MongoJSONEncoder, ObjectIdConverter
import jwt
### config ###
app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://127.0.0.1:27017/pythonrest'
app.json_encoder = MongoJSONEncoder
app.url_map.converters['objectid'] = ObjectIdConverter
mongo = PyMongo(app)
User = mongo.db.user


def gentoken(payload):
    return jwt.encode(payload, 'superverysecretkey', algorithm='HS256')


### Routes ###
# Register
@app.route('/register', methods=['POST'])
def register():
    body = request.json
    name = body.get('name')
    email = body.get('email')
    password = body.get('password')
    #all fields are required
    if not email or not name or not password:
        return jsonify({'error': 'name, email and password are required'})
    #check if user exist in database
    user = User.find_one({'email': email})
    if user:
        return jsonify({'message': 'User Already Exists'})
    # hash the password and save to db
    hashedPassword = hashpw(password.encode(), gensalt(12))
    id = User.insert({
        'name': name,
        'email': email,
        'password': hashedPassword.decode()
    })
    token = gentoken({'_id': str(id), 'name': name})
    return jsonify({
        'message': 'Successfully registered',
        'token': token.decode(),
    })


# Login
@app.route('/login', methods=['POST'])
def login():
    body = request.json
    email = body.get('email')
    password = body.get('password')
    #all fields are required
    if not email or not password:
        return jsonify({'error': 'email and password are required'})

    #check if user exist in database
    user = User.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User does not exist, please register'})
    #check if password match
    isValid = checkpw(password.encode(), user.get('password').encode())
    if isValid:
        token = gentoken({'_id': str(user['_id']), 'name': user['name']})
        return jsonify({
            'message': 'Successfully logged in',
            'token': token.decode()
        })
    else:
        return jsonify({'message': 'Incorrect password'})


# show all users
@app.route('/users')
def show_users():
    data = User.find({})
    # List users in a list
    users = [user for user in data]
    # hide password
    for user in users:
        del user['password']
    return jsonify({'users': users})


# show single user
@app.route('/users/<objectid:userId>')
def show_user(userId):
    user = User.find_one({'_id': userId})
    #hide password
    del user['password']
    return jsonify({'user': user})


if __name__ == '__main__':
    app.run(debug=True)