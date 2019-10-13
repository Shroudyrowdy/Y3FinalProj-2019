#Y3 CEP Final Project -- written by Sue Zheng Yong and Timothy Chia Zi Xiang
#General modules
from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_sqlalchemy  import SQLAlchemy

#Modules for forms
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SelectField, IntegerField
from wtforms.validators import InputRequired, Email, Length, NumberRange
from wtforms.fields.html5 import DateField

#Module for security
from werkzeug.security import generate_password_hash, check_password_hash

#Modules for logging in and making admin functions work
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView

#Module for sending emails
from flask_mail import Mail, Message

#Initialising app and configuring application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Dontknowwhatthisisfor'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://miswlhpxgajndp:a6887c765e2b743b68fbb91edd5882662f10caa5e08b912600dc3cd5d5dbbd07@ec2-54-225-205-79.compute-1.amazonaws.com:5432/da44fnkc6vvncp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['DEBUG'] = True
app.config['TESTING'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'ceplostnfound@gmail.com'
app.config['MAIL_PASSWORD'] = 'LRnRbLdNkbfvsQ48'
app.config['MAIL_DEFAULT_SENDER'] = ('Admin from LostnFound Site','ceplostnfound@gmail.com')
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_SUPRESS_SEND'] = False
app.config['MAIL_ASCII_ATTACHMENTS'] = False
mail = Mail(app)

bootstrap = Bootstrap(app)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Users(UserMixin, db.Model):
    #Table for users containing all additional details
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    password = db.Column(db.String)
    name = db.Column(db.String)
    classes = db.Column(db.String)
    phone = db.Column(db.Integer)
    email = db.Column(db.String)
    #Admin will indicate True if user is admin and False if user is not admin
    admin = db.Column(db.Boolean, default = False)

class Reports(db.Model):
    #Table for reports of Lost items
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    description = db.Column(db.String)
    location = db.Column(db.String)
    #Check for data type for dates
    date = db.Column(db.Date)
    tag = db.Column(db.String)
    reporter_user = db.Column(db.String)
    claimed = db.Column(db.Boolean)
    claimant_user = db.Column(db.String)

class Counters(db.Model):
    #Table for counter-claims (when you see that someone else has claimed your item)
    id = db.Column(db.Integer, primary_key=True)
    disputer_id = db.Column(db.Integer)
    #Report_id is the id of the report that this person is disputing
    report_id = db.Column(db.Integer)
    #Process is the "stage" that the counter-claim is in ("Pending/Not started", "In progress", "Resolved") This is for the Admin to view
    title = db.Column(db.String)
    description = db.Column(db.String)
    process = db.Column(db.String)

class MyModelView(ModelView):
    #View to let admin see tables
    def is_accessible(self):
        #Checks if user is registered admin before allowing them to access tables
        if current_user.is_authenticated:
            return current_user.admin
        return False
    def inaccessible_callback(self, name, **kwargs):
        #If user is not authenticated, send them to login page
        return redirect(url_for('login'))

class MyAdminIndexView(AdminIndexView):
    #View to let admin see tables
    def is_accessible(self):
        #Checks if user is registered admin before allowing them to access admin page
        if current_user.is_authenticated:
            return current_user.admin
        return False
    def inaccessible_callback(self, name, **kwargs):
        #If user is not authenticated, send them to login page
        return redirect(url_for('login'))

admin = Admin(app, index_view=MyAdminIndexView())
admin.add_view(MyModelView(Users,db.session))
admin.add_view(MyModelView(Reports,db.session))
admin.add_view(MyModelView(Counters,db.session))

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#All forms used
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    name = StringField('Full name', validators=[InputRequired()])
    phone = IntegerField('Phone Number', validators=[InputRequired(), NumberRange(min=0,max=99999999)])
    classes = StringField('Class',validators=[InputRequired(), Length(min=2,max=2)])

class ReportForm(FlaskForm):
    name = StringField('Summary of Found Item', validators=[InputRequired(), Length(max=25)])
    #Form to report that you have found something you think has been lost
    description = TextAreaField('Description of item', validators=[InputRequired()])
    tag = SelectField('Type of item', validators=[InputRequired()], choices=[('','Please select a tag'), ('Bottle', 'Bottle'), ('Phone', 'Phone')])
    location_found = StringField('Location', validators=[InputRequired()])
    date_found = DateField('DD/MM/YYYY', validators=[InputRequired()],  format='%Y-%m-%d')

class SearchForm(FlaskForm):
    #Form for searching for reports of found items
    tag = SelectField('Type of item', validators=[InputRequired()], choices=[('','Please select a tag'), ('Bottle', 'Bottle'), ('Phone', 'Phone')])
    claimed = BooleanField('Claimed')

class CounterForm(FlaskForm):
    #Form to make counter claims
    title = StringField('Short Title', validators=[InputRequired(), Length(max=25)])
    description = TextAreaField('Explanation of Situation', validators=[InputRequired()])

class ASearchForm(FlaskForm):
    #Form for searching for counter claims (for admins)
    pro = SelectField('Process', validators=[InputRequired()], choices=[('','Please select a tag'), ('New', 'New'), ('In Process', 'In Process'),('Completed','Completed')])

@app.route('/')
def index():
    #Homepage for people who are not logged in
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    #Login page
    #Initialises login form
    form = LoginForm()

    if form.validate_on_submit():
        #If form is submitted, check if username is found in database. If not, return "Invalid username or password"
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            #Hashing the password for additional protection
            if check_password_hash(user.password, form.password.data):
                #If username and password match, login_user and redirect them to dashboard. Else, return "Invalid username or password"
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return render_template('message.html', loggedin = current_user.is_authenticated, message='Invalid username or password!')

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
#Rmb to fix signup later
def signup():
    #Form to register
    form = RegisterForm()
    if form.validate_on_submit():
        #Account is created and password is hashed for extra protection
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = Users(username=form.username.data, password=hashed_password, name=form.name.data, email=form.email.data, classes = form.classes.data, phone = form.phone.data)
        db.session.add(new_user)
        db.session.commit()
        return render_template('message.html', loggedin = current_user.is_authenticated, message="Your account has been created!")
    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    #Main page
    return render_template('dashboard.html', adminstatus=current_user.admin, name=current_user.username)

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    #Form to report that you have found something that you think has been lost
    form = ReportForm()
    if form.validate_on_submit():
        new_report = Reports(name = form.name.data, description = form.description.data, location = form.location_found.data, date = form.date_found.data, tag = form.tag.data, reporter_user = current_user.username, claimed = False)
        db.session.add(new_report)
        db.session.commit()
        return render_template('message.html', adminstatus=current_user.admin, loggedin = current_user.is_authenticated, message="Your report has been made!")
    return render_template('report.html', adminstatus=current_user.admin, form=form)

@app.route('/logout')
@login_required
def logout():
    #Page for logging out
    logout_user()
    return redirect(url_for('index'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    #Search page (Allows user to pick a tag, as well as specify whether they are searching for claimed or unclaimed items)
    form = SearchForm()
    if form.validate_on_submit():
        #Redirect to results page
        t = form.tag.data
        c = form.claimed.data
        return redirect(url_for('results',t=t,c=c))
    return render_template('search.html', form=form, adminstatus=current_user.admin)

@app.route('/results')
@login_required
def results():
    #Page depicting results of search
    tag = request.args.get('t', None)
    claimed = request.args.get('c', None)
    results = Reports.query.filter_by(tag=tag, claimed=claimed).order_by(Reports.date.desc()).all()
    return render_template('results.html',results=results, adminstatus=current_user.admin)

@app.route('/reportpage/<string:id>', methods=['GET','POST'])
@login_required
def reportpage(id):
    #Page with report (of lost item)
    report = Reports.query.get(int(id))
    form = FlaskForm()
    if form.validate_on_submit():
        #"Form" is for students to click on to claim an item
        if report.claimed:
            report = Reports.query.get(int(id))
            if current_user.username == report.claimant_user:
                return render_template('message.html', adminstatus=current_user.admin, loggedin = current_user.is_authenticated, message = 'Item has been claimed')
            #If lost item is already claimed, then redirect to page for counter-claiming
            return redirect(url_for('reportclaim',id=id))
        else:
            #If lost item has not been claimed yet, set it to claimed
            report.claimed = True
            report.claimant_user = current_user.username
            db.session.commit()
            claimant_user = Users.query.filter_by(username = report.claimant_user).first()
            reporter_user = Users.query.filter_by(username = report.reporter_user).first()
            #Email is sent to the reporter_user
            msg = Message('Your report has been claimed', recipients=[reporter_user.email])
            msg.html = "Dear {},<br><br>The lost item you reported has been claimed by {}. Here are his details:<br><br>Name: {}<br>Class: {}<br>Email: {}<br>Phone number: {}".format(report.reporter_user, report.claimant_user, report.claimant_user, claimant_user.classes, claimant_user.email, claimant_user.phone)#
            mail.send(msg)
            return render_template('message.html', adminstatus=current_user.admin, loggedin = current_user.is_authenticated, message = 'Item has been claimed')
    return render_template('page.html', adminstatus=current_user.admin, report=report, form=form, current_user = current_user.username)

@app.route('/reportclaim', methods=['GET','POST'])
@login_required
def reportclaim():
    #Form for students to counter-claim an item
    reportid = request.args.get('id',None)
    form = CounterForm()
    if form.validate_on_submit():
        #Counter claim will be added to the list for the admins to begin looking into
        new_counter = Counters(disputer_id = current_user.id, report_id = reportid, title = form.title.data, description = form.description.data, process = "New")
        db.session.add(new_counter)
        db.session.commit()
        return render_template('message.html', adminstatus=current_user.admin, loggedin = current_user.is_authenticated, message = 'Counter Claim has been submitted')
    return render_template('cclaim.html',form=form, adminstatus=current_user.admin, reportid=reportid)

@app.route('/adminhome', methods=['GET','POST'])
@login_required
def adminhome():
    #Home page for admins (admins have to type url to get page)
    if not current_user.admin:
        #User is redirected back to dashboard if they aren't an admin
        return redirect(url_for('dashboard'))
    return render_template('ahome.html', adminstatus=current_user.admin)

@app.route('/adminclaims', methods=['GET','POST'])
@login_required
def adminclaims():
    #Page that allows admins to search for counter claims depending on their current process
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    form = ASearchForm()
    if form.validate_on_submit():
        process = form.pro.data
        return redirect(url_for('adminresults', p=process))
    return render_template('asearch.html', form = form, adminstatus=current_user.admin)

@app.route('/adminresults')
@login_required
def adminresults():
    #Page containing list of counter claims for admin to click on after searching
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    process = request.args.get('p', None)
    results = Counters.query.filter_by(process=process).order_by(Counters.id.desc()).all()
    return render_template('aresults.html',results=results, adminstatus=current_user.admin)

@app.route('/cclaimpage/<string:id>', methods=['GET','POST'])
@login_required
def cclaimpage(id):
    #Page that displays the counter claim and allows admin to begin looking into it/close it
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    process = request.args.get('p', None)
    form = FlaskForm()
    cclaim = Counters.query.get(id)
    if form.validate_on_submit():
        #Depending on current "process" of counter claim, it will either be opened or closed
        if cclaim.process == "In Process":
            cclaim.process = "Completed"
        if cclaim.process == "New":
            cclaim.process = "In Process"
        db.session.commit()
        return render_template('amessage.html', adminstatus=current_user.admin, message = "Claim's process has been updated")
    return render_template('cpage.html',cclaim=cclaim, form=form, adminstatus=current_user.admin)

if __name__ == '__main__':
    app.run(debug=True)
