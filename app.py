from flask import Flask, request, render_template, redirect, url_for
from pymongo import MongoClient
from dotenv import load_dotenv
import bcrypt
import os
import re
from detection import detect_sqli, log_attack, is_ip_blocked, register_failed_attempt
from config import MONGO_URI, DB_NAME, COLLECTION_NAME

load_dotenv()
app = Flask(__name__)

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users_col = db[COLLECTION_NAME]

@app.route('/')
def index():
    return render_template("login.html")

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    if is_ip_blocked(ip):
        return "Your IP is blocked due to suspicious activity.", 403

    username = request.form.get("username")
    password = request.form.get("password")

    if detect_sqli(username) or detect_sqli(password):
        log_attack(ip, username, password)
        register_failed_attempt(ip)
        return "SQL Injection Detected! Access Denied.", 403

    user = users_col.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        return "Login Successful!"
    else:
        register_failed_attempt(ip)
        return "Invalid username or password."

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    ip = request.remote_addr
    if is_ip_blocked(ip):
        return "Your IP is blocked due to suspicious activity.", 403

    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        contact = request.form.get("contact")

        if len(username) < 3 or len(password) < 5:
            return "Username or password too short", 400
        if not re.match(r'^\d{10}$', contact):
            return "Invalid contact number", 400
        if users_col.find_one({"username": username}):
            return "Username already exists!", 409

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users_col.insert_one({"username": username, "password": hashed_pw, "contact": contact})
        return redirect(url_for('index'))

    return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)