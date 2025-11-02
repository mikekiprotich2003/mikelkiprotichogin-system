from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["StudentDataHub"]
users_collection = db["users"]

# Helper function to get next login
def get_next_login(current_login_time):
    return users_collection.find_one(
        {'last_login': {'$gt': current_login_time}},
        sort=[('last_login', 1)]
    )

# Login route
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = users_collection.find_one({"email": email})

        if user and check_password_hash(user["password"], password):
            session["user"] = email

            # Update last_login timestamp
            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'last_login': datetime.utcnow()}}
            )

            # Get next user who logged in after this one
            current_user = users_collection.find_one({'email': email})
            next_user = get_next_login(current_user['last_login'])

            if next_user:
                return f"""
                    Welcome back, {email}.<br>
                    After your spark lit the system, the next soul to log in was <b>{next_user['username']}</b> 
                    at <i>{next_user['last_login']}</i>. The chain continues…
                """
            else:
               return render_template("welcome.html", email=email, next_user=next_user)

        else:
            flash("Invalid email or password")

    return render_template("login.html")

# Signup route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        if users_collection.find_one({"email": email}):
            flash("Email already exists")
        else:
            users_collection.insert_one({
                "username": username,
                "email": email,
                "password": password
            })
            flash("Account created! Please log in.")
            return redirect(url_for("login"))

    return render_template("signup.html")

# Forgot password route
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = users_collection.find_one({"email": email})
        if user:
            flash("A password reset link would be sent to your email (mock).")
        else:
            flash("Email not found")
    return render_template("forgot_password.html")

if __name__ == "__main__":
   import os

port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port)
