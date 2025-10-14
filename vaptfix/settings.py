import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent

# MongoDB URL
MONGO_DB_URL = os.getenv("MONGO_DB_URL")


RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
DEBUG = os.getenv("DEBUG", "True") == "True"
ALLOWED_HOSTS = ['localhost', '127.0.0.1','vapt-backend.onrender.com','808d3a4404a9.ngrok-free.app']
# Google OAuth Settings
GOOGLE_OAUTH2_CLIENT_ID = os.getenv("GOOGLE_OAUTH2_CLIENT_ID", "727499952932-0v6984jl4eg37ak60d4851vkbkf0itb7.apps.googleusercontent.com")
GOOGLE_OAUTH2_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH2_CLIENT_SECRET", "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")
# DEBUG = False  # Make sure this is True for local dev

# Microsoft Teams OAuth Settings (Add these after Google OAuth settings)
MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID", "your-microsoft-client-id")
MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET", "your-microsoft-client-secret")
MICROSOFT_TENANT_ID = os.getenv("MICROSOFT_TENANT_ID", "common") 
# MICROSOFT_REDIRECT_URI = os.getenv("MICROSOFT_REDIRECT_URI", "http://localhost:3000")
MICROSOFT_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"




# Optional: separate flag for reCAPTCHA testing
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
    "risk_criteria"
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
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
            # 'host': MONGO_DB_URL,
            'host': 'mongodb+srv://arshmittal740:ARSHMITTAL12@cluster0.9cj3n.mongodb.net/',
        }
    }
}

AUTH_USER_MODEL = "users.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Updated JWT configuration for UUID primary key
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",        # Changed from "_id" to "id"
    "USER_ID_CLAIM": "user_id",
}

# EMAIL CONFIG (SendGrid)
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.sendgrid.net"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "apikey"
EMAIL_HOST_PASSWORD = os.getenv("SENDGRID_API_KEY") 
DEFAULT_FROM_EMAIL = "arshmittal740@gmail.com"

# Expose API key for utils.py
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

FRONTEND_URL = "http://localhost:3000",


# Microsoft OAuth URLs (tenant-specific)
# MICROSOFT_AUTH_URL = f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize"
# MICROSOFT_TOKEN_URL = f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/token"

# Required scopes
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
# Slack OAuth Settings
SLACK_CLIENT_ID = os.getenv("SLACK_CLIENT_ID", "your-slack-client-id")
SLACK_CLIENT_SECRET = os.getenv("SLACK_CLIENT_SECRET", "your-slack-client-secret")
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "your-slack-signing-secret")

# Slack OAuth URLs
SLACK_AUTH_URL = "https://slack.com/oauth/v2/authorize"
SLACK_TOKEN_URL = "https://slack.com/api/oauth.v2.access"
# Slack API scopes
SLACK_SCOPES = [
    'channels:read',           # View basic information about public channels
    'channels:write',          # Create and manage channels
    'chat:write',             # Send messages as your app
    'users:read',             # View people in a workspace
    'users:read.email',       # View email addresses of people
    'groups:read',            # View basic information about private channels
    'groups:write',           # Create and manage private channels
    'im:read',                # View basic information about direct messages
    'im:write',               # Start direct messages with people
    'mpim:read',              # View basic information about group direct messages
    'mpim:write',             # Start group direct messages
    'team:read',              # View the name, email domain, and icon for workspaces
]

# JIRA OAuth Settings
JIRA_CLIENT_ID = os.getenv("JIRA_CLIENT_ID", "your-jira-client-id")
JIRA_CLIENT_SECRET = os.getenv("JIRA_CLIENT_SECRET", "your-jira-client-secret")
JIRA_REDIRECT_URI = os.getenv("JIRA_REDIRECT_URI", "http://localhost:8000/api/admin/users/jira/callback/")

# JIRA OAuth URLs
JIRA_AUTH_URL = "https://auth.atlassian.com/authorize"
JIRA_TOKEN_URL = "https://auth.atlassian.com/oauth/token"
JIRA_API_URL = "https://api.atlassian.com"

# JIRA OAuth Scopes
JIRA_SCOPES = [
    'read:jira-user',
    'read:jira-work',
    'write:jira-work',
    'manage:jira-project',
    'manage:jira-configuration',
    'read:me'
    
]

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://vapt-backend.onrender.com",
    "https://login.microsoftonline.com",
    "https://graph.microsoft.com",
    "https://slack.com",              
    "https://api.slack.com",  
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5502",
    "http://127.0.0.1:5502",
    "https://auth.atlassian.com",  
    "https://api.atlassian.com",
]

CORS_ALLOW_ALL_ORIGINS = DEBUG  # Allow all origins in development

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
MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# Logging configuration
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


