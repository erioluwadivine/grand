from flask import Flask,render_template,request,redirect, url_for,session,flash
from flask_wtf import Form
import os
from wtforms import TextField, PasswordField, FileField, SelectField
from wtforms.validators import InputRequired, Email, DataRequired, Length
from datetime import datetime
from werkzeug import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
ALLOWED_EXTENSIONS = (['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app = Flask(__name__)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER,pw=POSTGRES_PW,url=POSTGRES_URL,db=POSTGRES_DB)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.realpath('.') +'/static/img'
app.secret_key = 'some_random_key'


class sign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
#

    def __init__(self, username, password, email, ):
        self.username = username
        self.password = password
        self.email = email


    def check_password(self, password):
        return check_password_hash(self.password, password)


class d_blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    content = db.Column(db.Text)
    image_path = db.Column(db.UnicodeText)

class profiles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    displayimage = db.Column(db.String(70), nullable=False)
    about = db.Column(db.String(1000), nullable=False)
    otherprofile = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)

class post_portfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    about = db.Column(db.Text)
    img_path = db.Column(db.UnicodeText)


class post_portfolio_photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    about = db.Column(db.Text)
    img_path = db.Column(db.UnicodeText)
db.create_all()


class RegistrationForm(Form):
    username = TextField("first_name", validators =  [InputRequired()])
    email = TextField('email', validators=[DataRequired(), Email(message=None), Length(min=6, max=40)])
    password = PasswordField('Password', validators = [InputRequired()])
    check_password = PasswordField('check_password', validators = [InputRequired()])



class LoginForm(Form):
    email = TextField('email', [InputRequired(), Email()])
    password = PasswordField('Password', [InputRequired()])


def allowed_file(filename):
    return '.' in filename and filename.lower().rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route("/")
def index():
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    six_port = post_portfolio.query.limit(3).all()
    three_post = d_blog.query.limit(3).all()
    return render_template("index.html",posts=three_post, port=six_port, user=user, the_user=the_user)


@app.route("/read_more/port/<int:post_id>")
def read_art(post_id):
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    post = post_portfolio.query.filter_by(id=post_id).one()
    return render_template('read_more_art.html', post=post, post_id=post_id, the_user=the_user, user=user)


@app.route("/read_more/photo/<int:post_id>")
def read_photo(post_id):
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    post = post_portfolio_photo.query.filter_by(id=post_id).one()
    return render_template("read_more_photo.html", post=post, post_id=post_id, user=user, the_user=the_user)


@app.route("/portfolio/art")
def portfolio():
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    port_art = post_portfolio.query.order_by(post_portfolio.date_posted.desc()).all()
    return render_template("portfolio.html", posts=port_art, user=user, the_user=the_user)


@app.route("/editprofile", methods=["POST", "GET"])
def editprofile():
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    if request.method == "POST":
        if not session.get('username'):
            return render_template("login.html")
        try:
            current_username = session.get("username")
            img = request.files['displayimage']
            username = request.form['username']
            about = request.form['about']
            otherprofile = request.form['otherprofile']
            displayimage = ''
            if img:
                displayimage = secure_filename(img.filename)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], displayimage))
            user = profiles.query.filter_by(username=current_username)
            user.username = username
            user.about = about
            user.otherprofile = otherprofile
            user.displayimage = displayimage
            db.session.commit()
            return url_for(profile)
        except Exception as e:
            return (str(e))
    return render_template("editprofile.html", the_user=the_user, user=user)


@app.route("/blog/comment")
def comment ():
    return "<h1>hi<h1>"

@app.route("/portfolio/photo")
def portfolio_photo():
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    port_photo = post_portfolio_photo.query.order_by(post_portfolio_photo.date_posted.desc()).all()
    return render_template("portfolio_photo.html", posts=port_photo, the_user=the_user, user=user)

@app.route("/blog")
def blog():
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    all_post = d_blog.query.order_by(d_blog.date_posted.desc()).all()
    three_post = d_blog.query.limit(3).all()
    return render_template('blog.html', posts=all_post, three_post=three_post,user=user, the_user=the_user)


@app.errorhandler(404)
def page_not_found( e ):
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    return render_template("pages-404.html", the_user=the_user, user=user), 404

@app.route("/profile/<username>")
def profile(username):
    p_user = session.get("username")
    user = profiles.query.filter_by(username=username).first()
    if not user:
        return render_template("pages-404.html")
    user = profiles.query.filter_by(username=username)
    the_user = profiles.query.filter_by(username=p_user)
    return render_template("profile.html", posts=user, p_user=p_user, the_user=the_user  )

@app.route("/service")
def service():
    return render_template("services.html")


@app.route("/portfolio/add_portfolio", methods=["POST", "GET"])
def add_portfolio():
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    if not session.get('username'):
        return render_template("login.html")
    if request.method == "POST":
        try:
            img = request.files['img']
            author = session.get("username")
            title = request.form['title']
            about = request.form['about']
            select = request.form["category"]
            filename = ''

            if img:
                filename = secure_filename(img.filename)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            if select == "Photography":
                port = post_portfolio_photo(author=author, title=title, img_path=filename, about=about,  date_posted=datetime.now())
                db.session.add(port)
                db.session.commit()
                port_added = "portfolio successfully added"
                return render_template("portfolio.html", port_added=port_added, the_user=the_user, user=user)
            else:
                port = post_portfolio(author=author, title=title, img_path=filename, about=about, date_posted=datetime.now())
                db.session.add(port)
                db.session.commit()
                port_added = "portfolio successfully added"
                return render_template("portfolio.html", port_added=port_added, the_user=the_user, user=user)
        except Exception as e:
            return (str(e))
    return render_template("add_portfolio.html", the_user=the_user)


@app.route("/read_more/<int:post_id>")
def read_more(post_id):
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    post = d_blog.query.filter_by(id=post_id).one()
    return render_template('read_more.html', post=post, post_id=post_id, user=user, the_user=the_user)

@app.route("/portfolio/<username>")
def portfolio_user(username):
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    port = post_portfolio.query.filter_by(author=username).all()
    profile = profiles.query.filter_by(username=username).all()
    return render_template("portname.html", port=port, profile=profile, the_user=the_user)

@app.route("/portfoliophoto/<username>")
def portfolio_user_photo(username):
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    profile = profiles.query.filter_by(username=username).all()
    port = post_portfolio_photo.query.filter_by(author=username).all()
    return render_template("portphoto.html", profile=profile, port=port, the_user=the_user, user=user)


@app.route("/profileblog/<username>")
def profileblog(username):
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    profile = profiles.query.filter_by(username=username).all()
    port = d_blog.query.filter_by(author=username).all()
    return render_template("profileblog.html", profile=profile, port=port, user=user, the_user=the_user)

@app.route("/signup", methods=["POST", "GET"])
def signup():
    if request.method == "POST" :
        try:
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            check_password = request.form['check_password']
            displayimage = "thumbnail.png"
            otherprofile = "user has no profiles yet"
            about = "user has no about for now"
            if check_password != password:
                not_match = "passwords doesnt match"
                return render_template("signup.html", not_match=not_match)
            existing_user = sign.query.filter_by(email=email, username=username)
            if not existing_user:
                existing_user = "sorry this email or userma,e has been registered"
                return render_template("signup.html", existing_user=existing_user)
            user = sign(username=username, email=email, password=password)
            profile = profiles(displayimage=displayimage, about=about, email=email, username=username,
                               otherprofile=otherprofile)
            db.session.add(profile)
            db.session.add(user)
            db.session.commit()
            msg = "you have succesfully signed up now go login"
            return render_template("login.html" , msg=msg)
        except Exception as e:
            return (str(e))
    return render_template("signup.html")


@app.route("/blog/createblog", methods =["POST", "GET"])
def createblog():
    user = session.get("username")
    the_user = sign.query.filter_by(username=user)
    if not session.get('username'):
        return render_template("login.html")
    if request.method == "POST":
        try:
            image = request.files['image']
            title = request.form['title']
            content = request.form['content']
            author = session.get("username")
            filename = ''
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            u_blog = d_blog(author=author, title=title, image_path=filename, content=content,  date_posted=datetime.now())
            db.session.add(u_blog)
            db.session.commit()
            blog_added = "blog successfully added"
            return render_template("blog.html", blog_added=blog_added)
        except Exception as e:
            return (str(e))
    return render_template ("create_blog.html", the_user=the_user, user=user)


@app.route("/faq")
def faq():
    return render_template("faq.html")


@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username')
        log_out = 'You have successfully logged out.'
        return redirect(url_for('index', logout=log_out))
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('username'):
        logged_in = "you are already logged in"
        return render_template("login.html", logged_in=logged_in)
    form = LoginForm(request.form)
    if request.method == 'POST':
        username = request.form.get('username')
        login_password = request.form.get('login_password')
        existing_user = sign.query.filter_by(username=username, password=login_password).first()

        if not existing_user:
            not_exist = "incorrect username or password"
            return render_template('login.html', not_exist=not_exist)
        session['username'] = username
        login = "you are now logged in "
        return render_template("index.html", login=login)
    if form.errors:
        not_login = "something is not right please reload page and try again"
        return render_template("login.html", not_login=not_login)
    return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True)