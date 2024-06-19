from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:rootd@localhost/db'
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    string_field = db.Column(db.String(120))

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    string_field = request.json.get('string_field', None)
    user = User(username=username, password=password, string_field=string_field)
    db.session.add(user)
    db.session.commit()
    return jsonify(success=True)

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    user = User.query.filter_by(username=username).first()
    if user and user.password == password:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token)
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@app.route('/user/<username>', methods=['GET', 'PUT'])
@jwt_required
def get_user(username):
    if request.method == 'GET':
        user = User.query.filter_by(username=username).first()
        return jsonify(string_field=user.string_field)
    elif request.method == 'PUT':
        user = User.query.filter_by(username=username).first()
        user.string_field = request.json['string_field']
        db.session.commit()
        return jsonify(success=True)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)