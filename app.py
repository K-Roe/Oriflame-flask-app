from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# instantiate application and database
app = Flask(__name__)
app.config["SECRET_KEY"] = "mysecret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clients.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)

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

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
# Registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# Login form
class LoginForm(FlaskForm):
  email = StringField('Email', validators=[DataRequired(), Email()])
  password = PasswordField('Password', validators=[DataRequired()])
  remember = BooleanField('Remember Me')
  submit = SubmitField('Login')

# Home_page route and login route
@app.route("/", methods=["GET", "POST"])
def home():
    form = LoginForm(csrf_enabled=False)
    if form.validate_on_submit():
        # query User here:
        user = User.query.filter_by(email=form.email.data).first()
        # check if a user was found and the form password matches here:
        if user and user.check_password(form.password.data):
            # login user here:
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('landing', _external=True, _scheme='https'))
        else:
            return redirect(url_for('login', _external=True, _scheme='https'))
    return render_template('home_page.html', form=form)

# user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# registration route
@app.route("/reg", methods=["GET", "POST"])
def reg_page():
    form = RegistrationForm(csrf_enabled=False)
    if form.validate_on_submit():
        # define user with data from form here:
        user = User(username=form.username.data, email=form.email.data)
        # set user's password here:
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
    return render_template("Reg.html", title='Register', form=form)

@app.route('/landing_page')
def landing():
  # grab all guests and display them
  current_users = User.query.all()
  return render_template('landing_page.html', current_users = current_users)

# user route
@app.route('/user/<username>')
@login_required
def user(username):
  user = User.query.filter_by(username=username).first_or_404()
  return render_template('user.html', user=user)

if __name__ == '__main__':
    context = ('/cert.pem','/key.pem')
    app.run(debug=True, ssl_context=context)