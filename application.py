from flask import Flask, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_login import LoginManager
from passlib.hash import sha256_crypt
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Length

## DB and LoginManger##
db = SQLAlchemy()
loginManager = LoginManager()

## Models for the database ##

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(30), nullable=False)

    clucks = db.relationship('Cluck', backref='author', lazy=True)

class Cluck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cluck = db.Column(db.String(300), nullable=False)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    timeline = db.relationship('Timeline', lazy=True)

class Timeline(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cluckID = db.Column(db.Integer, db.ForeignKey('cluck.id'), default=None)

## Forms to interact with the html##

class Register(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=6, max=30)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=12)])
    register = SubmitField('Register')

class Login(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=6, max=30)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=12)])
    login = SubmitField('Log In')

class NewCluck(FlaskForm):
     cluck = TextAreaField('Cluck', validators=[Length(min=1, max=300)])
     newCluck = SubmitField('Cluck')


## Initializes the program
def create_instance():

    app = Flask(__name__)
    database = "clucker.db" # sets the database name
    app.config['SECRET_KEY'] = '75438f77a0a66421e74dd86f08fe854b329ac65b08bb8aebfb17dfe935ad2f30' #sets the secret key for connection
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + database #sets the app to use our database
    db.init_app(app)
    
    with app.app_context():
        db.create_all() #creates the dtaabse when the app has initialized

    loginManager.login_view = 'unauthenticated' #sets the unauthenticated route as the starting point
    loginManager.init_app(app)

    return app

app = create_instance() ## sets app to the create_instance function


## Routes ##
@loginManager.user_loader
def initialiseUser(id):
    return db.session.query(User).get(int(id)) ##Gets the current user that is in session

@app.route('/')
def unauthenticated():
    if current_user.is_authenticated:   # if user logs in, it redirects them to the timeline
        return redirect(url_for('timeline'))
    else:   ## if not, its back to the login
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():

    registerForm = Register()   # initializes the form as our register form class

    if registerForm.validate_on_submit():   #if it fits the required validators, it checks if the user is in the databse already
        userCheck = User.query.filter_by(username=registerForm.username.data).first()

        if userCheck != None:   # if suer exists in database, returns a flash error
             flash('REGISTER FAIL', 'fail')
             return render_template('register.html', form=registerForm)
        else: #if successful, creates the user
            encrpytedPassword = sha256_crypt.encrypt(str(registerForm.password.data))   #encrypts password
            user = User(username=registerForm.username.data, password=encrpytedPassword)    #creates user object
            db.session.add(user)    # adds user to the database
            db.session.commit()
            flash('REGISTER SUCCESS', 'success')
    return render_template('register.html', form=registerForm)

@app.route('/login', methods=['GET', 'POST'])
def login():

    loginForm = Login() # initializes the form as our login form class

    if loginForm.validate_on_submit(): #if it fits the required validators, it checks if the user is in the databse already
        userExists = User.query.filter_by(username=loginForm.username.data).first()

        if userExists != None:  # if the user exists, proceed
            password = userExists.password
            if sha256_crypt.verify(loginForm.password.data, password):  #if the ecnrpyted password matches the form
                login_user(userExists, remember=True)   #logins in user and rememebrs them by use of the users cookies
                flash('LOGIN SUCCESS', 'success')
                return redirect(url_for('timeline'))    # redirects logged in user to authenticated page
            else:   #if fail, flash error
                flash('LOGIN FAIL', 'failure')
                return render_template('login.html', form=loginForm)
    return render_template('login.html', form=loginForm)


@app.route('/timeline', methods=['GET', 'POST'])
@login_required
def timeline():

    newUserCluck = NewCluck()   # initializes the form as our newcluck form class
    timelineClucks = Cluck.query.order_by(desc(Cluck.id))  # initializes this as the result of querying all the clucks

    if newUserCluck.validate_on_submit():   #if it fits the required validators, proceeds

        userCluck = Cluck(cluck=newUserCluck.cluck.data, author=current_user)   #creates cluck object
        db.session.add(userCluck)   #adds the cluck object to the database
        db.session.commit()

        updateTimeline = Timeline(cluckID=userCluck.id) #creates new timeline onject to update
        db.session.add(updateTimeline)  # adds the update to the timeline
        db.session.commit()

        return redirect(url_for('timeline'))
    return render_template('timeline.html', user=current_user, cluck=newUserCluck, timeline=timelineClucks)

@app.route('/account', methods=['GET'])
@login_required
def account():
    return render_template('account.html', username=current_user.username) #lets the user see their account - WIP

@app.route('/logout')
def logout():
    logout_user()   #logs out the user
    return redirect(url_for('login'))   #redirects to the login page


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, port=8080)              
