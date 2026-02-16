import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv(override=True)
BASE_DIR = Path(__file__).resolve().parent.parent


MONGO_DB_URL = os.getenv("MONGO_DB_URL")


RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
DEBUG = os.getenv("DEBUG", "True") == "True"

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

ALLOWED_HOSTS = [host.strip() for host in """
localhost,
127.0.0.1,
deaf387e4d71.ngrok-free.app,
localhost:5173,
38.242.247.151,
vaptbackend.secureitlab.com
""".split(",")]

DATA_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50MB


GOOGLE_OAUTH2_CLIENT_ID = os.getenv("GOOGLE_OAUTH2_CLIENT_ID", "")
GOOGLE_OAUTH2_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH2_CLIENT_SECRET", "")

MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID", "")
MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET", "")
MICROSOFT_TENANT_ID = os.getenv("MICROSOFT_TENANT_ID", "")
MICROSOFT_REDIRECT_URI = os.getenv("MICROSOFT_REDIRECT_URI", "https://vaptbackend.secureitlab.com")

MICROSOFT_AUTH_URL = f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize"
MICROSOFT_TOKEN_URL = f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/token"



RECAPTCHA_SKIP = DEBUG
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt",

    "corsheaders",
    "users",
    "location",
    "users_details",
    "risk_criteria",
    "upload_report",
    "admindashboard",
    "adminregister",
    "adminasset",
    "scope",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "vaptfix.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "vaptfix.wsgi.application"

DATABASES = {
    'default': {
        'ENGINE': 'djongo',
        'NAME': 'vaptfix',
        'CLIENT': {
            'host': 'mongodb+srv://arshmittal740:ARSHMITTAL12@cluster0.9cj3n.mongodb.net/',
        }
        # 'CLIENT': {'host': os.getenv("MONGO_DB_URL")}
    }
}


AUTH_USER_MODEL = "users.User"



AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",      
    "USER_ID_CLAIM": "user_id",
}


EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.sendgrid.net"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "apikey"
EMAIL_HOST_PASSWORD = os.getenv("SENDGRID_API_KEY") 
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL")

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

FRONTEND_URL = os.getenv("FRONTEND_URL", "https://vapt-frontend-liart.vercel.app")


MICROSOFT_SCOPES = [
    'https://graph.microsoft.com/User.Read',
    'https://graph.microsoft.com/User.ReadBasic.All',       
    'https://graph.microsoft.com/Team.ReadBasic.All',
    'https://graph.microsoft.com/Team.Create',             
    'https://graph.microsoft.com/Channel.Create',           
    'https://graph.microsoft.com/Channel.ReadWrite.All',    
    'https://graph.microsoft.com/Channel.Delete.All',      
    'https://graph.microsoft.com/ChannelMessage.Send',      
    'https://graph.microsoft.com/Group.ReadWrite.All',     
    'https://graph.microsoft.com/TeamMember.ReadWrite.All', 
    'https://graph.microsoft.com/ChannelMember.ReadWrite.All',
    'https://graph.microsoft.com/Directory.ReadWrite.All',  
    'offline_access'
]

SLACK_CLIENT_ID = os.getenv("SLACK_CLIENT_ID", "")
SLACK_CLIENT_SECRET = os.getenv("SLACK_CLIENT_SECRET", "")
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")
SLACK_REDIRECT_URI = os.getenv("SLACK_REDIRECT_URI", "")

SLACK_AUTH_URL = "https://slack.com/oauth/v2/authorize"
SLACK_TOKEN_URL = "https://slack.com/api/oauth.v2.access"

SLACK_SCOPES = [
    'channels:read',           
    'channels:write',       
    'chat:write',             
    'users:read',            
    'users:read.email',     
    'groups:read',            
    'groups:write',           
    'im:read',                
    'im:write',               
    'mpim:read',             
    'mpim:write',           
    'team:read',              
]

JIRA_CLIENT_ID = os.getenv("JIRA_CLIENT_ID", "")
JIRA_CLIENT_SECRET = os.getenv("JIRA_CLIENT_SECRET", "")
JIRA_REDIRECT_URI = os.getenv("JIRA_REDIRECT_URI", "http://localhost:8000/api/admin/users/jira/callback/")


JIRA_AUTH_URL = "https://auth.atlassian.com/authorize"
JIRA_TOKEN_URL = "https://auth.atlassian.com/oauth/token"
JIRA_API_URL = "https://api.atlassian.com"


JIRA_SCOPES = [
    'read:jira-user',
    'read:jira-work',
    'write:jira-work',
    'manage:jira-project',
    'manage:jira-configuration',
    'read:me'
    
]

# CORS_ALLOWED_ORIGINS = [
#     "http://localhost:3000",
#     "http://127.0.0.1:3000",
#     "https://vapt-backend.onrender.com",
#     "https://login.microsoftonline.com",
#     "https://graph.microsoft.com",
#     "https://slack.com",              
#     "https://api.slack.com",  
#     "http://localhost:8000",
#     "http://127.0.0.1:8000",
#     "http://localhost:5502",
#     "http://127.0.0.1:5502",
#     "https://auth.atlassian.com",  
#     "https://api.atlassian.com",
#     "http://localhost:5173",
# ]


CORS_ALLOWED_ORIGINS = [origin.strip() for origin in """
http://localhost:3000,
http://127.0.0.1:3000,
http://localhost:5173,
http://127.0.0.1:5173,
http://localhost:8000,
http://127.0.0.1:8000,
http://localhost:5502,
http://127.0.0.1:5502,
https://vapt-frontend-liart.vercel.app,
https://login.microsoftonline.com,
https://graph.microsoft.com,
https://slack.com,
https://api.slack.com,
https://auth.atlassian.com,
https://api.atlassian.com,
https://vaptbackend.secureitlab.com
""".split(",")]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# CORS_ALLOW_ALL_ORIGINS = True  

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'users': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}


CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "signup-otp-cache",
    }
}