from flask import Flask, render_template, request, redirect, session,make_response
from flask_session import Session
from datetime import date, timedelta
from flask_sqlalchemy import SQLAlchemy 
import pymysql
import os
from werkzeug.utils import secure_filename
import hashlib
import time
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from pprint import pprint

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

from flask_jwt_extended import unset_jwt_cookies

pymysql.install_as_MySQLdb()

configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = 'Insert_your_api_key'

api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))


#  Intializing the application

app = Flask(__name__)

# Backend Connection

local_server = True

app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root@localhost/login_details"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "password"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"] 
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
app.config["JWT_COOKIE_HTTPONLY"] = True
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=10)
jwt = JWTManager(app)

db = SQLAlchemy(app)

# Making a Directory to Store the images
UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create a class 
class login_details(db.Model):
    '''sno,userid,username,email,password,account_type, exam_roll, semester'''

    sno = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email_id = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    account_type = db.Column(db.String(10), nullable=False)
    exam_roll = db.Column(db.String(20), nullable=False)
    semester = db.Column(db.Integer, nullable=False)

class book_details(db.Model):
    '''sno,userid,username,email,password,account_type'''

    sno = db.Column(db.Integer, primary_key=True)
    bookName = db.Column(db.String(50), nullable=False)
    bookAuthor = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    image_filename = db.Column(db.String(150), nullable=False)

class book_issued(db.Model):
    '''sno, stud_name, book_name, stud_id, stud_email, semester, time'''
    sno = db.Column(db.Integer, primary_key=True)
    stud_name = db.Column(db.String(100), nullable=False)
    book_name = db.Column(db.String(100), nullable=False)
    stud_id = db.Column(db.String(50), nullable=False)
    stud_email = db.Column(db.String(100), nullable=False)
    semester = db.Column(db.Integer, nullable=False)
    issue_time = db.Column(db.String(50), nullable=False)
    return_time = db.Column(db.String(50), nullable=False)

@app.route('/')
def home():
    

    return render_template('home.html')

@app.route('/signin', methods=['GET','POST'])
def signin():
    
    if(request.method == 'POST'):
        login_email = request.form.get('email_id')
        login_password = request.form.get('Password')

        Email_Addr = login_details.query.filter_by(email_id=login_email).first()

        hashed_password = hashlib.sha256(login_password.encode()).hexdigest()
        if Email_Addr and Email_Addr.password == hashed_password:
            if Email_Addr.account_type == 'admin':

                access_token = create_access_token(identity=login_email)
                resp = make_response(redirect('/dashboard'))
                resp.set_cookie('access_token_cookie', access_token)
                return resp
            else:
                access_token = create_access_token(identity=login_email)
                resp = make_response(redirect('/stuDashboard'))
                resp.set_cookie('access_token_cookie', access_token)
                return resp

        # If the username or password is incorrect, show an error message
        error_message = "Invalid username or password. Please try again."
        return render_template('signin.html', error=error_message)
    
     # If it's a GET request, show the login form
    return render_template('signin.html')


@app.route('/signup', methods=['GET','POST'])
def signup():

    if(request.method =='POST'):
        register_username = request.form.get('username')
        register_email = request.form.get('emailId')
        register_password = request.form.get('password')
        register_exam_roll = request.form.get('exam_roll')
        register_semester = request.form.get('semester')

        # Hashing the Password 
        hashed_password = hashlib.sha256(register_password.encode()).hexdigest()

        

        # Now here validating the if the exam_roll is already being used or not
    
        if(login_details.query.filter_by(exam_roll=register_exam_roll).first()):
            error_message = "The Exam Roll Number is already registered, please enter correct roll number"
            return render_template('signup.html', custom_error=error_message)
        else:
            register = login_details(username=register_username,email_id=register_email,password=hashed_password,exam_roll=register_exam_roll, semester=register_semester, account_type='student')
            db.session.add(register)
            db.session.commit()

            # Now sending mail for successfully creating the account

            subject = "Account is Created successfully"
            html_content = f"""<html><body><h1>You have create the Account successfully</h1><p>Username : {register_username} </p> <p>Email : {register_email} </p></body></html>"""
            sender = {"name":"Admin","email":"admin@dspmu.ac.in"}
            to = [{"email":register_email,"name":register_username}]
            
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, html_content=html_content, sender=sender, subject=subject)
            
            try:
                api_response = api_instance.send_transac_email(send_smtp_email)
                pprint(api_response)
            except ApiException as e:
                print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)

        return redirect("/signin")      
    
    return render_template('signup.html')

@app.route('/signout')
def signout():
    resp = make_response(redirect('/signin'))
    unset_jwt_cookies(resp)
    return resp

@app.route('/dashboard')
@jwt_required()
def dashboard():
   
    # Now got the email id from the jwt token
    current_user=get_jwt_identity()
    print(current_user)

    Email_Addr = login_details.query.filter_by(email_id=current_user).first()
    # print(Email_Addr.account_type)

    account_type = Email_Addr.account_type

    if(account_type == 'admin'):
        return render_template('dashboard.html', get_jwt_identity=get_jwt_identity)
    else:
        resp = make_response(redirect('/signin'))
        unset_jwt_cookies(resp)
        return resp
        


@app.route('/addBook',methods=['GET','POST'])
@jwt_required()
def addBook():
    # Implementing Authorization
    current_user=get_jwt_identity()
    Email_Addr = login_details.query.filter_by(email_id=current_user).first()
    account_type = Email_Addr.account_type
    if(account_type == 'admin'):
        if(request.method =='POST'):
            book_name = request.form.get('bookName')
            author_name = request.form.get('authorName')
            book_qty = request.form.get('quantity')
            book_img = request.files['image']
            # Here rename the images files to somethings meaning full
            filename = secure_filename(book_img.filename)
            def generate_unique_filename(filename):
                name, ext = os.path.splitext(filename)
                return book_name + ext
            
            new_filename = generate_unique_filename(filename)
            book_img.save(UPLOAD_FOLDER + new_filename)

            add_book = book_details(bookName=book_name,image_filename=new_filename,bookAuthor=author_name,quantity=book_qty)
            db.session.add(add_book)
            db.session.commit() 

            return redirect("/dashboard")     
    
        return render_template('addBook.html', get_jwt_identity=get_jwt_identity)
    else:
       resp = make_response(redirect('/signin'))
       unset_jwt_cookies(resp)
       return resp 
  

@app.route('/issueBook', methods=['GET','POST'])
@jwt_required()
def issueBook():
    # Implementing Authorization
    current_user=get_jwt_identity()
    Email_Addr = login_details.query.filter_by(email_id=current_user).first()
    account_type = Email_Addr.account_type
    if(account_type == 'admin'):
        if(request.method =='POST'):
            student_name = request.form.get('studentName')
            book_name = request.form.get('bookName')
            student_Id = request.form.get('studentID')
            student_email = request.form.get('studentEmail')
            student_semester = request.form.get('semester')
            
            # Here we are doing current date for borrwing the book
            current_date = date.today()
            formatted_date = current_date.strftime("%d-%m-%Y")
            book_borrow_date = formatted_date

            later_date = current_date + timedelta(days=7)
            formatted_later_date = later_date.strftime("%d-%m-%Y")
            return_book_date = formatted_later_date
            # Now Here we need to do Validation whether it is a student or not
            check_authorization = login_details.query.filter_by(email_id=student_email).first()
            if check_authorization is not None and check_authorization.account_type == 'student':
                
                issued_books_count = book_issued.query.filter_by(stud_email=student_email).count()

                # Check if the user has already issued the maximum allowed number of books
                if issued_books_count >= 2:
                    error_message = "You have already issued the maximum allowed number of books."
                    return render_template('issueBook.html', custom_error=error_message)

                #Checking whether it is in stock the application and check whether it is avaliable
                book_quantity = book_details.query.filter_by(bookName=book_name).first()
                if book_quantity.quantity < 1:
                    out_of_stock_message = f"The book '{book_name}' is currently out of stock."
                    return render_template('issueBook.html', custom_error=out_of_stock_message)
                else:
                    issue_book = book_issued(stud_name=student_name,book_name=book_name,stud_id=student_Id,stud_email=student_email, semester=student_semester, issue_time=book_borrow_date, return_time=return_book_date)
                    db.session.add(issue_book)
                    db.session.commit() 
                    book_quantity.quantity -= 1
                    db.session.commit()

                    # Now sending mail for when issued booked 

                    subject = "Book Issued successfully"
                    html_content = f"""<html><body><h1>Your book is issued successfully</h1><p>Username : {student_name} </p> <p>BookName : {book_name} </p></body></html>"""
                    sender = {"name":"Admin","email":"admin@dspmu.ac.in"}
                    to = [{"email":student_email,"name":student_name}]
                    
                    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, html_content=html_content, sender=sender, subject=subject)
                    
                    try:
                        api_response = api_instance.send_transac_email(send_smtp_email)
                        pprint(api_response)
                    except ApiException as e:
                        print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)




                return redirect("/dashboard")  
            
            else:
                return render_template('issueBook.html', custom_error='Check the details you have entered')

        return render_template('issueBook.html', get_jwt_identity=get_jwt_identity)
    else:
       resp = make_response(redirect('/signin'))
       unset_jwt_cookies(resp)
       return resp 
    
@app.route('/viewBook')
@jwt_required()
def viewBook():
    
    viewallBooks= book_details.query.all()
    

    return render_template('viewBook.html', viewallBooks = viewallBooks, get_jwt_identity=get_jwt_identity)

@app.route('/returnBook', methods=['GET','POST'])
@jwt_required()
def returnBook():

    # Implementing Authorization
    current_user=get_jwt_identity()
    Email_Addr = login_details.query.filter_by(email_id=current_user).first()
    account_type = Email_Addr.account_type
    if(account_type == 'admin'):
        if(request.method =='POST'):
            student_email = request.form.get('studentEmail')
            book_name = request.form.get('bookName')

            
            user_info = book_issued.query.filter_by(stud_email=student_email).first()
            if user_info:
                book_quantity = book_details.query.filter_by(bookName=book_name).first()
                if book_quantity is not None :
                    db.session.delete(user_info)
                    db.session.commit()
                    book_quantity.quantity += 1
                    db.session.commit()

                    # Now sending mail for when issued booked 

                    subject = "Returned the book successfully"
                    html_content = f"""<html><body><h1>Your have returned the Book</h1><p>Username : {user_info.stud_name} </p> <p>BookName : {user_info.book_name} </p></body></html>"""
                    sender = {"name":"Admin","email":"admin@dspmu.ac.in"}
                    to = [{"email":user_info.stud_email,"name":user_info.stud_name}]
                        
                    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, html_content=html_content, sender=sender, subject=subject)
                        
                    try:
                        api_response = api_instance.send_transac_email(send_smtp_email)
                        pprint(api_response)
                    except ApiException as e:
                        print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)


                    return redirect("/dashboard")
                else:
                    return render_template('returnBook.html', custom_error='Please check the details you have entered')      

        return render_template('returnBook.html', get_jwt_identity=get_jwt_identity)
    else:
       resp = make_response(redirect('/signin'))
       unset_jwt_cookies(resp)
       return resp  

# stuDashboard
@app.route('/stuDashboard', methods=['GET', 'POST'])
@jwt_required()
def stuDashboard():    
    value_of_email = get_jwt_identity()

    Email_Addr = login_details.query.filter_by(email_id=value_of_email).first()
    book_quantity = book_issued.query.filter_by(stud_email=value_of_email).first()

    student_name = Email_Addr.username
    student_email = Email_Addr.email_id
    semester = Email_Addr.semester
    

    # New variable to Query multiple books issued to the user
    book_query_variable = book_issued.query.with_entities(book_issued.book_name).filter(
        book_issued.stud_email == value_of_email
    ).all()
    borrowedBooks = [book[0] for book in book_query_variable]

    return render_template('student_dashboard.html', student_name=student_name, student_email=student_email, semester=semester, borrowed_books=borrowedBooks, get_jwt_identity=get_jwt_identity)

@app.route('/stuDashboard/resetPassword', methods=['GET', 'POST'])
@jwt_required()
def resetPassword():

    if not get_jwt_identity():
        return redirect("/signin")
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    

    # Here we are checking session token for current user email address
    value_of_email = get_jwt_identity()

    Email_Addr = login_details.query.filter_by(email_id=value_of_email).first()
    
    # Request should be post 
    if(request.method =='POST'):
        # Here we are checking the current password with the hashed value

        hashed_current_password = hashlib.sha256(current_password.encode()).hexdigest()
        
        if(Email_Addr.password == hashed_current_password):
            hash_new_password = hashlib.sha256(new_password.encode()).hexdigest()
            Email_Addr.password = hash_new_password
            db.session.commit()
            session.clear()

            # When Password reset is done for the specific account, Send the email for successfully updating the account

            

            subject = "You account Password Reset Successfully for the account"
            html_content = f"""<html><body><h1>Your have sucessfully reset the password</h1><p>Username : {Email_Addr.username} </p> <p>Email : {Email_Addr.email_id} </p></body></html>"""
            sender = {"name":"Admin","email":"admin@dspmu.ac.in"}
            to = [{"email":Email_Addr.email_id,"name":Email_Addr.username}]
                
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, html_content=html_content, sender=sender, subject=subject)
                
            try:
                api_response = api_instance.send_transac_email(send_smtp_email)
                pprint(api_response)
            except ApiException as e:
                print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)

            return redirect('/signin')
        else:
            return render_template('studentPasswordReset.html', custom_error="You have enter wrong current password, Please enter the correct one!!")


    return render_template('studentPasswordReset.html', get_jwt_identity=get_jwt_identity)

if __name__ == "__main__":
    app.run(debug=True, port=8000)
