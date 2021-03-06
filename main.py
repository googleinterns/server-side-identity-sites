import sqlite3
import sys

from flask import Flask, request, render_template, session, url_for

sys.path.append('../server-side-identity')
from gsi.verification import verifiers
from gsi.verification import exceptions
sys.path.append('../server-side-identity-sites')

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
    c.execute('''CREATE TABLE IF NOT EXISTS users (given_name text, family_name text, email text, state text, password text, federated int);''')
    close_db(conn)


def insert_user(given_name, family_name, email, state, password, federated=0):
    """Inserts a user into the 'users' table of the database"""
    conn, c = open_db()
    c.execute('''INSERT INTO users VALUES (?,?,?,?,?,?);''', (given_name, family_name, email, state, password, federated))
    close_db(conn)


def is_email_registered(email):
    """Determines if a given email is already registered in our database"""
    conn, c = open_db()
    user_email = c.execute('''SELECT * FROM users WHERE email=?;''', (email,)).fetchone()
    close_db(conn)
    return user_email != None


def is_password_correct(email, password):
    """Determines if a given password matches the stored password for a particular email. 
    The email must be in the database"""
    conn, c = open_db()
    stored_password = c.execute('''SELECT password FROM users WHERE email=?;''', (email,)).fetchone()
    close_db(conn)
    return password == stored_password[0]


def get_first_name(email):
    """Retrieves the given name of a user in our database with the given email.  Username must be in the db"""
    conn, c = open_db()
    first_name = c.execute('''SELECT given_name FROM users WHERE email=?;''', (email,)).fetchone()
    close_db(conn)
    return first_name[0]


def is_account_federated(email):
    """Determines if a given email is associated with a federated account in our database. If the email is not registered, this 
    method returns False"""
    registered = is_email_registered(email)
    if not registered:
        return False
    
    conn, c = open_db()
    federated = c.execute('''SELECT federated FROM users WHERE email=?;''', (email,)).fetchone()
    close_db(conn)
    return federated[0] == 1


def make_user_federated(email):
    """Make the account associated with the given email a federated account. The email must be registered in the database"""
    conn, c = open_db()
    c.execute('''UPDATE users SET federated=1 WHERE email=?;''', (email,))
    close_db(conn)
    

@app.route('/home', methods=['GET'])
def home_page():
    """Display the home page of the site"""
    print("Demo home page")
    return render_template('home.html')


@app.route('/register', methods=['GET'])
def display_register():
    """Display the user registration page of the site"""
    print("Registration page")
    return render_template('register.html')


@app.route('/generator', methods=['GET'])
def display_generator():
    """Display the code generation page of the site"""
    print("Code Generation page")
    return render_template('generator.html')


@app.route('/generator', methods=['POST'])
def generate_code():
    """Generate the code given the user's input"""
    print("Generating Code")
    client_id = request.values.get('client')
    print(client_id)
    g_suite_domain = request.values.get('domain')
    
    if g_suite_domain:
        code = """
from gsi.verification import verifiers
from gsi.verification import exceptions

#receive id_token from login endpoint

CLIENT_APP_IDS = ["{}"]
G_SUITE_DOMAIN = "{}"
verifier = verifiers.GoogleOauth2Verifier(client_ids=CLIENT_APP_IDS,
                                          g_suite_hosted_domain=G_SUITE_DOMAIN)

try:
    decoded_token = verifier.verify_token(id_token)
    #use decoded_token to complete user sign in

except (ValueError, exceptions.GoogleVerificationError):
    #invalid token, prompt user to try again
""".format(client_id, g_suite_domain)
        return render_template('generator.html', code=code, client_id=client_id, 
                               g_suite=g_suite_domain)
        
        
    else:
        code = """
from gsi.verification import verifiers
from gsi.verification import exceptions

#receive id_token from login endpoint

CLIENT_APP_IDS = ["{}"]
verifier = verifiers.GoogleOauth2Verifier(client_ids=CLIENT_APP_IDS)

try:
    decoded_token = verifier.verify_token(id_token)
    #use decoded_token to complete user sign in

except (ValueError, exceptions.GoogleVerificationError):
    #invalid token, prompt user to try again
""".format(client_id)
        return render_template('generator.html', code=code, client_id=client_id, 
                               g_suite=g_suite_domain)
    

@app.route('/register-user', methods=['POST'])
def register_new_user():
    """Register a new user with the given information"""
    print("Registering User")
    fname = request.values.get('fname')
    lname = request.values.get('lname')
    email = request.values.get('email').lower()
    state = request.values.get('state')
    password = request.values.get('passwrd')
    #should really encrypt and salt passwords, but this is just a demo
    
    create_user_table()
    registered_email = is_email_registered(email)
        
    if registered_email:
        #send them back to a login/registration page
        print("Reg Failed: Existing Email")
        error_message = "The provided email is already linked to a registred account. Please provide another email."
        return render_template('register.html', reg_error=error_message)
        
    else:
        print("Registering New User")
        insert_user(fname, lname, email, state, password, federated=0)
        return render_template('account_success.html', name=fname, registration=str(True))

@app.route('/', methods=['GET'])
@app.route('/login', methods=['GET'])
def display_login():
    """Display the user login page of the site"""
    print("Login page")
    return render_template('login.html')


@app.route('/login-user', methods=['POST'])
def login_existing_user():
    """Attempt to log in an existing user into the database if the given password and email are 
    consistent with the database"""
    print("Logging in User")
    email = request.values.get('email').lower()
    password = request.values.get('passwrd')
    
    create_user_table()
    registered_email = is_email_registered(email)
    if not registered_email:
        error_message = "The given email is not associated with any registered account. Please provide a registered email."
        return render_template('login.html', login_error=error_message)
    
    correct_password = is_password_correct(email, password)
    if correct_password:
        first_name = get_first_name(email)
        return render_template('account_success.html', name=first_name, login=str(True))
    
    error_message = "The given password for the specified account is incorrect."
    return render_template('login.html', login_error=error_message)


@app.route('/gsi-token', methods=['POST'])
def handle_google_sign_in():
    """Handle signing in when Google sends the token to our server directly"""
    print('Handling User Request from Google Button or OneTap')
    
    #Verify CSRF double submit cookie
    csrf_token_cookie = request.cookies.get('g_csrf_token')
    if not csrf_token_cookie:
        return render_template('home.html', error="Google Sign In failed. No CSRF token in provided cookie.")
    
    csrf_token_body = request.values.get('g_csrf_token')
    if not csrf_token_body:
        return render_template('home.html', error="Google Sign In failed. No CSRF token in post body.")
    
    if csrf_token_body != csrf_token_cookie:
        return render_template('home.html', error="Google Sign In failed. Failed to verify double submit cookie.")
    
    id_token = request.values.get('credential')
    
    CLIENT_APP_IDS = ["443130310905-s9hq5vg9nbjctal1dlm2pf8ljb9vlbm3.apps.googleusercontent.com"] #CLIENT IDs of apps using this backend
    verifier = verifiers.GoogleOauth2Verifier(client_ids=CLIENT_APP_IDS)

    try:
        decoded_token = verifier.verify_token(id_token) #use decoded_token to complete user sign in
        
        email = decoded_token.get_email().lower()
        given_name = decoded_token.get_given_name()
        
        create_user_table()
        registered = is_email_registered(email)
        federated = is_account_federated(email)
        
        if registered:
            
            if federated:
                return render_template('account_success.html', name=given_name, login=str(True))
            
            else: #legacy user - link accounts
                session['decoded_token'] = decoded_token.to_json()
                error_message = ("The email associated with this Google account is already registered. " 
                             "Please link this existing account to your Google account.")
                return render_template('link_existing_account.html', link_error=error_message, google_email=email)
            
        else: #unregistered user
            session['decoded_token'] = decoded_token.to_json() #session value must be serializable
            return render_template('register_googler.html')

    except (ValueError, exceptions.GoogleVerificationError):
        #invalid token, prompt user to try again
        return render_template('home.html', error="Google Sign In failed. The ID Token was invalid.")


@app.route('/register-googler', methods=['POST'])
def register_new_googler():
    """Register the new Google account in the federated database using the provided information"""
    user_info = verifiers.GoogleDecodedToken(session['decoded_token']) #json to DecodedToken object
    state = request.values.get('state')
    password = request.values.get('passwrd')
    first_name = user_info.get_given_name()
    last_name = user_info.get_family_name()
    email = user_info.get_email().lower()
    
    create_user_table()
    insert_user(first_name, last_name, email, state, password, federated=1)
    
    return render_template('account_success.html', name=first_name, registration=str(True))


@app.route('/link-login', methods=['POST'])
def link_existing_user():
    """Attempt to link an existing account to a Google account"""
    user_info = verifiers.GoogleDecodedToken(session['decoded_token']) #json to DecodedToken object
    token_email = user_info.get_email().lower()
    email = request.values.get('email').lower()
    password = request.values.get('passwrd')
    
    if email != token_email:
        error_message = "The given email does not match the one associated with the Google Account. Please provide the correct email."
        return render_template('link_existing_account.html', link_error=error_message, google_email=token_email)
    
    correct_password = is_password_correct(email, password)
    if not correct_password:
        error_message = "The given password for the specified account is incorrect."
        return render_template('link_existing_account.html', link_error=error_message, google_email=token_email)
    
    make_user_federated(email)
    
    return render_template('account_success.html', name=get_first_name(email), link=str(True))

