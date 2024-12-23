# config.py
from dotenv import load_dotenv
import os

load_dotenv()

# Konfigurasi Keamanan
SECRET_KEY = os.getenv('SECRET_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Konfigurasi Aplikasi
APP_NAME = os.getenv('APP_NAME', 'Secure Streamlit App')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'False') == 'True'

# app.py
import streamlit as st
import hashlib
import sqlite3
from datetime import datetime, timedelta
from config import *
import re

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Drop tables if exist
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('DROP TABLE IF EXISTS audit_log')
    
    # Create users table with email column
    c.execute('''
        CREATE TABLE users
        (username TEXT PRIMARY KEY, 
         email TEXT UNIQUE,
         password TEXT,
         created_at TIMESTAMP)
    ''')
    
    # Create audit_log table
    c.execute('''
        CREATE TABLE audit_log
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
         username TEXT,
         action TEXT,
         timestamp TIMESTAMP)
    ''')
    conn.commit()
    conn.close()

# --- Security Functions ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(username, password):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE username=?', (username,))
    result = c.fetchone()
    conn.close()
    
    if result:
        return result[0] == hash_password(password)
    return False

def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def is_valid_username(username):
    # Username harus 4-20 karakter, hanya huruf, angka, dan underscore
    pattern = r'^[a-zA-Z0-9_]{4,20}$'
    return re.match(pattern, username) is not None

def is_valid_password(password):
    # Password minimal 8 karakter, harus mengandung huruf dan angka
    if len(password) < 8:
        return False
    if not re.search(r'[A-Za-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

def username_exists(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT 1 FROM users WHERE username=?', (username,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def email_exists(email):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT 1 FROM users WHERE email=?', (email,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def log_action(username, action):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO audit_log (username, action, timestamp) VALUES (?, ?, ?)',
              (username, action, datetime.now()))
    conn.commit()
    conn.close()

# --- Session Management ---
def init_session_state():
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
    if 'last_attempt' not in st.session_state:
        st.session_state.last_attempt = None
    if 'show_signup' not in st.session_state:
        st.session_state.show_signup = False

# --- Registration System ---
def register_user():
    st.title("Register")
    
    with st.form("registration_form"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        submitted = st.form_submit_button("Register")
        
        if submitted:
            if not is_valid_username(username):
                st.error("Username harus 4-20 karakter dan hanya boleh mengandung huruf, angka, dan underscore")
                return
            
            if not is_valid_email(email):
                st.error("Email tidak valid")
                return
            
            if not is_valid_password(password):
                st.error("Password harus minimal 8 karakter dan mengandung huruf dan angka")
                return
            
            if password != confirm_password:
                st.error("Password tidak cocok")
                return
            
            if username_exists(username):
                st.error("Username sudah digunakan")
                return
            
            if email_exists(email):
                st.error("Email sudah digunakan")
                return
            
            # Register user
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            try:
                c.execute('INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, ?)',
                         (username, email, hash_password(password), datetime.now()))
                conn.commit()
                log_action(username, "registered")
                st.success("Registrasi berhasil! Silakan login.")
                st.session_state.show_signup = False
            except Exception as e:
                st.error(f"Error during registration: {str(e)}")
            finally:
                conn.close()

# --- Login System ---
def login_page():
    st.title("Login")
    
    # Toggle between login and register
    if st.button("Need an account? Register here"):
        st.session_state.show_signup = True
        st.rerun()
        
    # Rate limiting check
    if (st.session_state.login_attempts >= 3 and 
        st.session_state.last_attempt and 
        datetime.now() - st.session_state.last_attempt < timedelta(minutes=15)):
        st.error("Too many login attempts. Please try again later.")
        return

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if verify_password(username, password):
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.login_attempts = 0
            log_action(username, "successful login")
            st.success("Successfully logged in!")
            st.rerun()
        else:
            st.session_state.login_attempts += 1
            st.session_state.last_attempt = datetime.now()
            log_action(username, "failed login attempt")
            st.error("Invalid username or password")

# --- Main Application ---
def main_app():
    st.title(APP_NAME)
    
    # Sidebar
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox("Choose a page", ["Home", "Profile", "Settings"])
    
    if st.sidebar.button("Logout"):
        log_action(st.session_state.username, "logout")
        st.session_state.authenticated = False
        st.session_state.username = None
        st.rerun()

    # Main content
    if page == "Home":
        st.header("Welcome to the Home Page")
        st.write(f"Hello, {st.session_state.username}!")
        
        # Example of secure form
        with st.form("secure_form"):
            sensitive_data = st.text_input("Enter sensitive data", type="password")
            submitted = st.form_submit_button("Submit")
            if submitted:
                # Here you would typically encrypt the data before storing
                log_action(st.session_state.username, "submitted sensitive data")
                st.success("Data securely stored!")

    elif page == "Profile":
        st.header("User Profile")
        st.write(f"Username: {st.session_state.username}")
        
        # Change password form
        with st.form("change_password"):
            old_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            
            if st.form_submit_button("Change Password"):
                if verify_password(st.session_state.username, old_password):
                    if new_password == confirm_password:
                        conn = sqlite3.connect('database.db')
                        c = conn.cursor()
                        c.execute('UPDATE users SET password=? WHERE username=?',
                                (hash_password(new_password), st.session_state.username))
                        conn.commit()
                        conn.close()
                        log_action(st.session_state.username, "changed password")
                        st.success("Password successfully changed!")
                    else:
                        st.error("New passwords don't match!")
                else:
                    st.error("Current password is incorrect!")

    elif page == "Settings":
        st.header("Settings")
        st.write("Application settings will appear here.")

# --- Main Execution ---
def main():
    init_db()
    init_session_state()
    
    if not st.session_state.authenticated:
        if st.session_state.show_signup:
            register_user()
            if st.button("Already have an account? Login here"):
                st.session_state.show_signup = False
                st.rerun()
        else:
            login_page()
    else:
        main_app()

if __name__ == "__main__":
    if DEBUG_MODE:
        st.write("⚠️ Debug mode is enabled")
    main()