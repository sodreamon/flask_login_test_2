from flask import Flask,render_template, request, flash, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import logout_user, login_user, LoginManager, login_required, current_user, UserMixin
from markupsafe import escape


app = Flask(__name__)


# 데이터 베이스 구역
app.config['SECRET_KEY'] = '9OLWxND4o83j4K4iuopO'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)

books = db.Table('books',
                db.Column('book_id', db.Integer, db.ForeignKey('book.id'), primary_key=True),
                db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                )

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    name = db.Column(db.String)
    books = db.relationship('Book', secondary=books, lazy='subquery',
                            backref=db.backref('users', lazy=True))

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, unique=True)












#홈 화면
@app.route('/')
def home():

    if 'name' in session:
        name = escape(session['name'])
        return render_template('home.html', name=name)
    return render_template('home.html')

@app.route('/profile')
@login_required
def profile():

    return render_template('profile.html', name=current_user.name)











#관리자
@app.route('/admin')
def admin():
    admin_n = 670112
    users = User.query.all()
    books = Book.query.all()
    return render_template('admin.html', users=users, books=books, admin_n=admin_n)

@app.route('/admin', methods=['POST'])
def admin_login():
    email = request.form.get('email')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        flash('접근 권한이 없습니다. 해당 접근 기록은 관리자에게 전송되었습니다.')
        return redirect(url_for('admin'))

    login_user(user)
    return redirect(url_for('admin'))

@app.route('/admin/<user>')
def admin_user(user):
    this_user = User.query.filter_by(id=user).first()
    user_books = this_user.books

    books = Book.query.all()
    return render_template('admin_user.html', user=this_user, user_books=user_books, books=books)

@app.route('/admin/<user>', methods=['POST'])
def admin_user_book(user):
    this_user = User.query.filter_by(id=user).first()
    book_id = request.form.getlist('book')

    for book_id in book_id:
        book = Book.query.filter_by(id=book_id).first()
        this_user.books.append(book)
        db.session.add(this_user)
        db.session.commit()

    del_books_id = request.form.getlist('del')
    for del_book in del_books_id:
        for db_book in this_user.books:
            if str(db_book.id) == del_book:
                this_user.books.remove(db_book)
                db.session.commit()

    return redirect(url_for('admin_user', user=this_user.id))













# 로그인, 회원가입
@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    same_user = User.query.filter_by(email=email).first()
    if same_user:
        flash('you have already')
        return redirect(url_for('signup'))

    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        flash('check your email or password')
        return redirect(url_for('login'))

    login_user(user, remember=remember)
    return redirect(url_for('profile'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/update')
@login_required
def update_user():
    return render_template('update_user.html')

@app.route('/update', methods=['POST'])
@login_required
def update_user_post():
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    new_re = request.form.get('new_re')

    if new_password != new_re:
        flash('새 비밀번호가 일치하지 않습니다.')
        return redirect(url_for('update_user'))

    user_id = current_user.id
    this_user = User.query.filter_by(id=user_id).first()
    this_user_old_password = this_user.password

    if not check_password_hash(this_user_old_password, old_password):
        flash('이전 비밀번호가 일치하지 않습니다.')
        return redirect(url_for('update_user'))

    User.query.filter_by(id=user_id).update(dict(password = generate_password_hash(new_password, method='sha256')))
    db.session.commit()

    return redirect(url_for('profile'))




#로그인 매니저
login_manager = LoginManager()
login_manager.login_view= 'login'
login_manager.init_app(app)

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)













#책
@app.route('/books')
def books():
    books_all = Book.query.all()
    return render_template('books.html', books=books_all)

@app.route('/books', methods=['POST'])
def book_post():
    title = request.form.get('title')

    new_book = Book(title=title)
    db.session.add(new_book)
    db.session.commit()

    return redirect(url_for('books'))












#유저
@app.route('/user_books')
@login_required
def user_books():
    user_id = session['_user_id']
    this_user = User.query.filter_by(id=user_id).first()
    this_user_books = this_user.books

    return render_template('user_books.html', this_user_books=this_user_books)











#앱 실행
if __name__ == '__main__':
    app.run(debug=True)