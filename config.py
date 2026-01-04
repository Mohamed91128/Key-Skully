import os
from datetime import timedelta
import base64

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production-super-secure'
    
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'app.db')
    
    KEY_VALID_HOURS = 24
    NEW_KEY_WAIT_HOURS = 1
    
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY') or 'kyauy6GAVPgXTUFBJ1aeSi2Lq-viti1_Pznammt-SKk='
    
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    PERMANENT_SESSION_LIFETIME = timedelta(hours=25)
