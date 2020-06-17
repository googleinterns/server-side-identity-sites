from flask import Flask, request, render_template, url_for
import sqlite3

app = Flask(__name__)
DB = './database.db'
CLIENT_ID = "443130310905-s9hq5vg9nbjctal1dlm2pf8ljb9vlbm3.apps.googleusercontent.com"


def open_db():
    """Opens a database connection for editing"""
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    return (conn, c)


def close_db(conn):
    """Closes the database connection"""
    conn.commit()
    conn.close()


def create_user_table():
    """Creates a 'users' table in our database IF ONE DOES NOT ALREADY EXIST.  Does nothing otherwise."""
    conn, c = open_db()
    c.execute('''CREATE TABLE IF NOT EXISTS users (given_name text, family_name text, email text, state text,                                                               username text, password text);''')
    close_db(conn)


def insert_user(given_name, family_name, email, state, username, password):
    """Inserts a user into the 'users' table of the database"""
    conn, c = open_db()
    c.execute('''INSERT INTO users VALUES (?,?,?,?,?,?);''', (given_name, family_name, email, state, username,                                                                      password))
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
    print(stored_password)
    return password == stored_password[0]


def get_first_name(username):
    """Gets the first name of the user with the given username. The username must be in the database"""
    conn, c = open_db()
    name = c.execute('''SELECT given_name FROM users WHERE username=?;''', (username,)).fetchone()
    close_db(conn)
    return name[0]


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
    
    if registered_email:
        #send them back to a login/registration page
        print("Reg Failed: Existing Email")
        return render_template('register_existing_email.html')
    
    if registered_username:
        #send them back to a login/registration page
        print("Reg Failed: Existing Username")
        return render_template('register_existing_username.html')
        
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
        return render_template('login_missing_username.html')
    
    correct_password = is_password_correct(username, password)
    if correct_password:
        first_name = get_first_name(username)
        return render_template('login_success.html', name=first_name)
    
    return render_template('incorrect_password.html')
        
    


        

    
    
    
    
    
    
    
    
    
    

