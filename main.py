from flask import Flask, request, render_template, redirect,url_for,session,flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, time, timedelta
import re

app=Flask(__name__)
app.secret_key="rjdk8741tao"
url="mongodb://localhost:27017/"

client=MongoClient(url)
db=client.flipkart
users=db.user

def is_password_strong(Password):
    if len(Password) < 8:
        return False
    if not re.search(r"[a-z]", Password) or not re.search(r"[A-Z]", Password) or not re.search(r"\d", Password):
        return False
    if not re.search(r"[!@#$%^&*()-+{}|\"<>]?", Password):
        return False
    return True

class user:
    def __init__(self,id,username,password):
        self.id=id
        self.username=username
        self.password=password

class SignupForm(FlaskForm):
    username=StringField("username",validators=[InputRequired(),Length(min=4,max=15)])
    password=PasswordField("password",validators=[InputRequired(),Length(min=8,max=15)])
    submit=SubmitField("Signup")
class LoginForm(FlaskForm):
    username=StringField("username",validators=[InputRequired(),Length(min=4,max=15)])
    password=PasswordField("password",validators=[InputRequired(),Length(min=8,max=15)])
    submit=SubmitField("Login")

@app.route("/signup",methods=["GET","POST"])
def signup():
    form=SignupForm()
    if form.validate_on_submit():
        name=form.username.data
        password=form.password.data
        hashed_password=generate_password_hash(password)
        if not is_password_strong(password):
            flash("Password must be atleast 8 letters long,a-z,A-Z,0-9,Symbols ",'danger')
            return redirect(url_for("signup"))
        data=users.find_one({"username":name})
        if data:
            flash("User Name taken :(", "danger")
            return redirect(url_for("signup"))
        log={"username":name,"password":password}
        flash("Successfully Signed in", "success")
        return redirect(url_for("login"))
    return render_template("signup.html",form=form)

@app.route("/login",methods=["GET","POST"])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        name=form.username.data
        password = form.password.data
        data=users.find_one({"username":name})
        if data:
            stored_hash_password=data["password"]
            if check_password_hash(stored_hash_password,password):
                current_user=user(id=str(data["_id"]),username=data["username"],password=data["password"])
                session["user_id"]=current_user.id
                flash("Successfully Logged in ")
                return redirect(url_for("flipkart"))
            else:
                flash("Invalid Credentials","Danger")
        else:
            flash("User Not Found!","danger")
    return render_template("login.html",form=form)

@app.route("/logout")
def logout():
    session.pop("user_id",None)
    flash("Logged Out","Success")
    return redirect(url_for("flipkart"))

def is_logged_in():
    return "user_id" in session

@app.route("/",methods=["GET","POST"])
def flipkart():
    return render_template("flipkart.html")

@app.route("/category1",methods=["GET","POST"])
def category():
    return render_template("category1.html")
if __name__ == "__main__":
    app.run(debug=True)