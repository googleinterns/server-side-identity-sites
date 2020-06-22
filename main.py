import sqlite3

from flask import Flask, request, render_template, session, url_for
from google.auth.transport import requests
from google.oauth2 import id_token

_DB = './database.db'
_CLIENT_ID = "443130310905-s9hq5vg9nbjctal1dlm2pf8ljb9vlbm3.apps.googleusercontent.com"

app = Flask(__name__)
app.secret_key = 'super secret string for demo website'


def open_db():
    """Opens a database connection for editing"""
    conn = sqlite3.connect(_DB)
    c = conn.cursor()
    return (conn, c)


def close_db(conn):
    """Closes the database connection"""
    conn.commit()
    conn.close()


def create_user_table():
    """Creates a 'users' table in our database IF ONE DOES NOT ALREADY EXIST.  Does nothing otherwise."""
    conn, c = open_db()
    c.execute('''CREATE TABLE IF NOT EXISTS users (given_name text, family_name text, email text, state text, username text, password text);''')
    close_db(conn)


def insert_user(given_name, family_name, email, state, username, password):
    """Inserts a user into the 'users' table of the database"""
    conn, c = open_db()
    c.execute('''INSERT INTO users VALUES (?,?,?,?,?,?);''', (given_name, family_name, email, state, username, password))
    close_db(conn)


def is_email_registered(email):
    """Determines if a given email is already registered in our database"""
    conn, c = open_db()
    user_email = c.execute('''SELECT * FROM users WHERE email=?;''', (email,)).fetchone()
    close_db(conn)
    return user_email != None


def is_username_registered(username):
    """Determines if a given username is already registered in our database"""
    conn, c = open_db()
    user = c.execute('''SELECT * FROM users WHERE username=?;''', (username,)).fetchone()
    close_db(conn)
    return user != None


def is_password_correct(username, password):
    """Determines if a given password matches the stored password for a particular username. 
    The username must be in the database"""
    conn, c = open_db()
    stored_password = c.execute('''SELECT password FROM users WHERE username=?;''', (username,)).fetchone()
    close_db(conn)
    return password == stored_password[0]


def get_first_name(username):
    """Retrieves the given name of a user in our database with the given username.  Username must be in the db"""
    conn, c = open_db()
    first_name = c.execute('''SELECT given_name FROM users WHERE username=?;''', (username,)).fetchone()
    close_db(conn)
    return first_name[0]


def create_federated_user_table():
    """Creates a 'federated_users' table in our database IF ONE DOES NOT ALREADY EXIST.  Does nothing otherwise."""
    conn, c = open_db()
    c.execute('''CREATE TABLE IF NOT EXISTS federated_users (given_name text, family_name text, email text, state text, username text);''')
    close_db(conn)


def insert_federated_user(given_name, family_name, email, state, username="NULL"):
    """Inserts a user into the 'federated_users' table of the database"""
    conn, c = open_db()
    c.execute('''INSERT INTO federated_users VALUES (?,?,?,?,?);''', (given_name, family_name, email, state, username))
    close_db(conn)

    
def is_federated_email_registered(email):
    """Determines if a given email is already registered in our federated database"""
    conn, c = open_db()
    user_email = c.execute('''SELECT * FROM federated_users WHERE email=?;''', (email,)).fetchone()
    close_db(conn)
    return user_email != None


@app.route('/', methods=['GET'])
def home_page():
    """Display the home page of the site"""
    print("Demo home page")
    return render_template('home.html')


@app.route('/register', methods=['GET'])
def display_register():
    """Display the user registration page of the site"""
    print("Registration page")
    return render_template('register.html')


@app.route('/register-user', methods=['POST'])
def register_new_user():
    """Register a new user with the given information"""
    print("Registering User")
    fname = request.values.get('fname')
    lname = request.values.get('lname')
    email = request.values.get('email').lower()
    state = request.values.get('state')
    username = request.values.get('usr')
    password = request.values.get('passwrd')
    #should really encrypt and salt passwords, but this is just a demo
    
    create_user_table()
    registered_email = is_email_registered(email)
    registered_username = is_username_registered(username)
    
    if username == "NULL" or username == "":
        #do not accept NULL or empty username. send them back to login/registration page
        print("Reg Failed: NULL or empty username")
        error_message = "Username cannot be NULL or empty"
        return render_template('register.html', reg_error=error_message)
        
    if registered_email:
        #send them back to a login/registration page
        print("Reg Failed: Existing Email")
        error_message = "The provided email is already linked to a registred account. Please provide another email."
        return render_template('register.html', reg_error=error_message)
    
    if registered_username:
        #send them back to a login/registration page
        print("Reg Failed: Existing Username")
        error_message = "The provided username is already linked to a registred account. Please provide another username."
        return render_template('register.html', reg_error=error_message)
        
    else:
        print("Registering New User")
        insert_user(fname, lname, email, state, username, password)
        return render_template('registration_success.html', name=fname)


@app.route('/login', methods=['GET'])
def display_login():
    """Display the user login page of the site"""
    print("Login page")
    return render_template('login.html')


@app.route('/login-user', methods=['POST'])
def login_existing_user():
    """Attempt to log in an existing user into the database if the given password and username are 
    consistent with the database"""
    print("Logging in User")
    username = request.values.get('usr')
    password = request.values.get('passwrd')
    
    create_user_table()
    registered_username = is_username_registered(username)
    if not registered_username:
        error_message = "The given username is not associated with any registered account. Please provide a registered username."
        return render_template('login.html', login_error=error_message)
    
    correct_password = is_password_correct(username, password)
    if correct_password:
        first_name = get_first_name(username)
        return render_template('login_success.html', name=first_name)
    
    error_message = "The given password for the specified account is incorrect."
    return render_template('login.html', login_error=error_message)


@app.route('/onetap-token', methods=['POST'])
def handle_onetap():
    """Handle signing in when Google sends the token to our server directly"""
    print('Handling User Request from OneTap')
    #Verify CSRF double submit cookie
    csrf_token_cookie = request.cookies.get('g_csrf_token')
    if not csrf_token_cookie:
        return render_template('home.html', error="Google Sign In failed. No CSRF token in provided cookie.")
    
    csrf_token_body = request.values.get('g_csrf_token')
    if not csrf_token_body:
        return render_template('home.html', error="Google Sign In failed. No CSRF token in post body.")
    
    if csrf_token_body != csrf_token_cookie:
        return render_template('home.html', error="Google Sign In failed. Failed to verify double submit cookie.")

    token = request.values.get('credential')
    user_info = verify_id_token(token, _CLIENT_ID)
    print(str(user_info))
    if not user_info:
        return render_template('home.html', error="Google Sign In failed. The ID Token was invalid.")
    
    email = user_info['email']
    create_federated_user_table()
    registered_fed = is_federated_email_registered(email)
    registered = is_email_registered(email)
    
    if registered_fed:
        return render_template('login_success.html', name=user_info['given_name'])
    elif registered:
        error_message = ("The email associated with this Google account is already registered. " 
                         "Please link this existing account to your Google account or sign in without Google")
        return render_template('link_existing_account.html', link_error=error_message)
    else:
        session['decoded_token'] = user_info
        return render_template('new_googler.html')


@app.route('/new-google-account', methods=['GET'])
def display_google_registration():
    """Display the registration page for a new Google account on the site"""
    return render_template('register_googler.html')


@app.route('/register-googler', methods=['POST'])
def register_new_googler():
    """Register the new Google account in the federated database using the provided information"""
    user_info = session['decoded_token']
    state = request.values.get('state')
    first_name = user_info['given_name']
    last_name = user_info['family_name']
    email = user_info['email']
    
    create_federated_user_table()
    insert_federated_user(first_name, last_name, email, state)
    
    return render_template('registration_success.html', name=first_name)


@app.route('/link-account', methods=['GET'])
def display_account_link():
    """Display the account link page for linking an existing account to a Google account"""
    return render_template('link_existing_account.html')


@app.route('/link-login', methods=['POST'])
def link_existing_user():
    """Attempt to link an existing account to a Google account"""
    username = request.values.get('usr')
    password = request.values.get('passwrd')
    
    create_user_table()
    registered_username = is_username_registered(username)
    if not registered_username:
        error_message = "The given username is not associated with any registered account. Please provide a registered username."
        return render_template('link_existing_account.html', link_error=error_message)
    
    correct_password = is_password_correct(username, password)
    if not correct_password:
        error_message = "The given password for the specified account is incorrect."
        return render_template('link_existing_account.html', link_error=error_message)

    user_info = session['decoded_token']
    state = request.values.get('state')
    first_name = user_info['given_name']
    last_name = user_info['family_name']
    email = user_info['email']
    
    create_federated_user_table()
    insert_federated_user(first_name, last_name, email, state, username)
    
    return render_template('link_success.html', name=first_name)


def verify_id_token(token, client_id):
    """Verify that a given id_token is valid and return the decoded user information if it is valid"""
    print("Begin Token Verification")
    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), client_id)
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError("Wrong Issuer")

        return idinfo

    except ValueError:
        return False