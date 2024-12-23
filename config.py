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