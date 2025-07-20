# Stories.d
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from models import db, User, Story, Comment
from forms import LoginForm, RegisterForm, StoryForm, CommentForm

app = Flask(_name_)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stories.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    stories = Story.query.order_by(Story.created_at.desc()).all()
    return render_template('index.html', stories=stories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing = User.query.filter_by(email=form.email.data).first()
        if existing:
            flash('Email already registered.', 'danger')
        else:
            hashed = generate_password_hash(form.password.data)
            new_user = User(email=form.email.data, password=hashed)
            db.session.add(new_user)
            db.session.commit()
            flash('Registered! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post_story():
    form = StoryForm()
    if form.validate_on_submit():
        story = Story(title=form.title.data, content=form.content.data, author_id=current_user.id)
        db.session.add(story)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('post.html', form=form)

@app.route('/story/<int:story_id>', methods=['GET', 'POST'])
def story_detail(story_id):
    story = Story.query.get_or_404(story_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Login to comment.", "warning")
            return redirect(url_for('login'))
        comment = Comment(content=form.content.data, story_id=story_id, author_id=current_user.id)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('story_detail', story_id=story_id))
    return render_template('story_detail.html', story=story, form=form)

if _name_ == '_main_':
    app.run(debug=True)
