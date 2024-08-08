from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from config import app, db, login_manager, bcrypt
from flask_login import UserMixin, login_user, logout_user, login_required, current_user

from app_classes import *

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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


@app.route('/direct-message/<string:recipiant>', methods=['GET', 'POST'])
@login_required
def direct_message(recipiant):
    user_exists = db.session.query(User.query.filter_by(username=recipiant).scalar() is not None)
    if not user_exists:
        return render_template("dashboard.html", username=current_user.username, incorrect_user = "true")



    session_messages = DirectMessage.query.filter(
        or_(
            and_(DirectMessage.sender == current_user.username, DirectMessage.receiver == recipiant),
            and_(DirectMessage.sender == recipiant, DirectMessage.receiver == current_user.username)
        )
    ).order_by(DirectMessage.timestamp.desc()).all()



    return render_template('dm.html', recipient=recipient, session_username=current_user.username, session_messages=session_messages)



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
    