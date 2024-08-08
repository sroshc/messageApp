from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'supersecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable =False)
    username = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default = datetime.utcnow)

class DirectMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

    def __repr__(self):
        return f'<DirectMessage {self.id} from {self.sender.username} to {self.receiver.username}>'

class DirectMessageForm(FlaskForm):
    content = StringField(validators=[
                           InputRequired(), Length(min=1, max=500)], render_kw={"placeholder": "message..."})
    
    submit = SubmitField('Register')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    

    def __repr__(self):
        return '<User %r>'% self.id

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=25)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_name = User.query.filter_by(username=username.data).first()
        if existing_user_name:
            raise ValidationError("username already exists")

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=25)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')



@app.route('/make-account', methods=['POST', 'GET'])
def make_account():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('makeaccount.html', process='made', form = form)



    return render_template('makeaccount.html', form=form)





@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/board')
@login_required
def board():
    messages = Message.query.order_by(Message.timestamp.desc()).all()
    return render_template('chat.html', messages=messages, session_username = current_user.username)

@app.route('/send', methods=['POST'])
@login_required
def send_message():
    content = request.form.get('content')
    if content:
        new_message = Message(content=content, username=current_user.username)
        db.session.add(new_message)
        db.session.commit()
    return jsonify(success=True)

@app.route('/messages')
def get_messages():
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    return jsonify([{'content': m.content, 'username': m.username, 'timestamp': m.timestamp.strftime('%H:%M')} for m in messages])


@app.route('/direct-message', methods=['POST'])
@login_required
def direct_message():
    recipient = request.form.get('username')
    users = User.query.all()
    users_extracted = [user.username for user in users]

    if recipient not in users_extracted:
        flash('that user does not exist')
        return render_template("dashboard.html", username=current_user.username, incorrect_user = "true")
    else:
        return render_template('dm.html', recipient=recipient, session_username=current_user.username)



@app.route('/get-users', methods=['GET'])
def get_users():
    users = User.query.all()
    users_extracted = [user.username for user in users]

    return jsonify(users_extracted)

@app.route('/')
def lander():
    return render_template('lander.html')


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  
    app.run(debug=True)
    