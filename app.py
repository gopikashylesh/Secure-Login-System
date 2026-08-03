from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
import re


app = Flask(__name__)


app.config['SECRET_KEY'] = '8f7c9d2a6e4b1f9c3d5e7a8b0c2d4e6f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# CSRF Protection
csrf = CSRFProtect(app)


# Security Headers
Talisman(
    app,
    force_https=False
)


db = SQLAlchemy(app)

bcrypt = Bcrypt(app)



class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)

    email = db.Column(db.String(120), unique=True, nullable=False)

    password = db.Column(db.String(255), nullable=False)

    failed_attempts = db.Column(db.Integer, default=0)

    locked_until = db.Column(db.DateTime, nullable=True)




with app.app_context():
    db.create_all()





@app.route("/")
def home():

    return render_template("login.html")






@app.route("/register", methods=["GET", "POST"])
def register():


    if request.method == "POST":


        username = request.form["username"].strip()

        email = request.form["email"].strip()

        password = request.form["password"]



        errors = []



        # Email validation

        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'


        if not re.match(email_pattern, email):

            errors.append("Enter a valid email address.")




        # Password validation

        if len(password) < 8:

            errors.append("Password must be at least 8 characters long.")



        if not any(char.isdigit() for char in password):

            errors.append("Password must contain at least one digit.")



        if not any(char.isupper() for char in password):

            errors.append("Password must contain at least one uppercase letter.")




        if errors:

            return render_template(
                "register.html",
                username=username,
                email=email,
                error=errors
            )





        if User.query.filter_by(username=username).first():

            return render_template(
                "register.html",
                username=username,
                email=email,
                error=["Username already exists."]
            )




        if User.query.filter_by(email=email).first():

            return render_template(
                "register.html",
                username=username,
                email=email,
                error=["Email already registered."]
            )





        hashed = bcrypt.generate_password_hash(password).decode("utf-8")



        user = User(
            username=username,
            email=email,
            password=hashed
        )



        db.session.add(user)

        db.session.commit()



        flash("Registration Successful. Please Login.")

        return redirect(url_for("home"))



    return render_template("register.html")









@app.route("/login", methods=["POST"])
def login():


    username = request.form["username"]

    password = request.form["password"]



    user = User.query.filter_by(username=username).first()



    if not user:

        flash("Invalid Username or Password")

        return redirect(url_for("home"))




    if user.locked_until and datetime.utcnow() < user.locked_until:

        flash("Account temporarily locked. Try again later.")

        return redirect(url_for("home"))





    if bcrypt.check_password_hash(user.password, password):


        user.failed_attempts = 0

        user.locked_until = None

        db.session.commit()



        session["user"] = user.username


        return redirect(url_for("dashboard"))





    user.failed_attempts += 1



    if user.failed_attempts >= 5:


        user.locked_until = datetime.utcnow() + timedelta(minutes=5)

        user.failed_attempts = 0




    db.session.commit()



    flash("Invalid Username or Password")

    return redirect(url_for("home"))









@app.route("/dashboard")
def dashboard():


    if "user" not in session:

        return redirect(url_for("home"))



    return render_template(
        "dashboard.html",
        username=session["user"]
    )











@app.route("/logout")
def logout():


    session.clear()


    flash("Logged out successfully.")


    return redirect(url_for("home"))







if __name__ == "__main__":

    app.run(debug=True)