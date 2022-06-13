from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash

# instantiate application and database
app = Flask(__name__)
app.config["SECRET_KEY"] = "mysecret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clients.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    joined_at = db.Column(db.DateTime(), default=datetime.utcnow, index = True)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')




class CommentForm(FlaskForm):
    comment = StringField("Comment")
    submit = SubmitField("Add Comment")

@app.route("/", methods=["GET", "POST"])
def home():
    form = RegistrationForm(csrf_enabled=False)
    if form.validate_on_submit():
        # define user with data from form here:
        user = User(username=form.username.data, email=form.email.data)
        # set user's password here:
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
    return render_template("home_page.html", title='Register', form=form)

