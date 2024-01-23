import uuid
from datetime import datetime, timedelta
from functools import wraps

# imports for PyJWT authentication
import jwt
from flask import Flask, jsonify, make_response, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "your secret key"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "postgresql://postgres:root@localhost:5432/flask"
db = SQLAlchemy(app)


class UserReg(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(225))


with app.app_context():
    db.create_all()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
            print(token)

        if not token:
            return jsonify({"message": "Token is missing !!"}), 401

        try:
            print("we are in try")
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            print(data)
            current_user = UserReg.query.filter_by(public_id=data["public_id"]).first()
            print(current_user)
        except:
            return jsonify({"message": "Token is invalid !!"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/user", methods=["GET"])
@token_required
def get_all_users(current_user):
    users = UserReg.query.all()

    output = []
    for user in users:
        output.append(
            {"public_id": user.public_id, "name": user.name, "email": user.email}
        )

    return jsonify({"users": output})


@app.route("/login", methods=["POST"])
def login():
    auth = request.form
    print(auth)
    if not auth or not auth.get("email") or not auth.get("password"):
        return make_response(
            "Could not verify",
            401,
            {"WWW-Authenticate": 'Basic realm ="Login required !!"'},
        )

    user = UserReg.query.filter_by(email=auth.get("email")).first()

    if not user:
        return make_response(
            "Could not verify",
            401,
            {"WWW-Authenticate": 'Basic realm ="User does not exist !!"'},
        )

    if check_password_hash(user.password, auth.get("password")):
        token = jwt.encode(
            {
                "public_id": user.public_id,
                "exp": datetime.utcnow() + timedelta(minutes=30),
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )
        # token.decode("UTF-8")
        return jsonify({"token": token}), 201

    return make_response(
        "Could not verify",
        403,
        {"WWW-Authenticate": 'Basic realm ="Wrong Password !!"'},
    )


# signup route
@app.route("/signup", methods=["POST"])
def signup():
    data = request.form

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    # print("---------------")
    # print(data)
    # print("--------------")
    # print(name)

    user = UserReg.query.filter_by(email=email).first()
    if not user:
        public_id = str(uuid.uuid4())
        print(public_id)
        user = UserReg(
            public_id=str(uuid.uuid4()),
            name=name,
            email=email,
            password=generate_password_hash(password),
        )

        db.session.add(user)
        db.session.commit()

        return make_response("Successfully registered.", 201)
    else:
        return make_response("User already exists. Please Log in.", 202)


@app.route("/")
def index():
    return "hiii gjg"


if __name__ == "__main__":
    app.run(debug=True)
