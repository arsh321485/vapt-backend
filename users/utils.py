from datetime import timedelta
import logging
from time import timezone
import requests
import sendgrid
from sendgrid.helpers.mail import Mail
from django.conf import settings
from users.models import User
import random
from django.core.cache import cache

logger = logging.getLogger(__name__)

class Util:
    @staticmethod
    def send_mail(data):
        """
        Send email using SendGrid API
        """
        try:
            sg = sendgrid.SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)
            mail = Mail(
                from_email=settings.DEFAULT_FROM_EMAIL,
                to_emails=data["to_email"],
                subject=data["subject"],
                plain_text_content=data["body"],
            )
            response = sg.send(mail)
            logger.info(f"SendGrid response: {response.status_code}")
            return response.status_code in [200, 201, 202]
        except Exception as e:
            logger.error(f"SendGrid send error: {str(e)}")
            return False
        
        # ✅ ADMIN FIRST-TIME SIGNUP EMAIL
    # ADMIN OTP EMAIL (SIGNUP)
    @staticmethod
    def send_signup_otp(email, otp=None):
        if otp is None:
            otp = str(random.randint(100000, 999999))
        
        # Cache OTP only (password stored separately)
        cache.set(f"signup_otp_{email}", otp, timeout=300)

        body = f"""
        Your OTP for VAPTFIX Admin Signup is: {otp}
        This OTP is valid for 5 minutes.
        """

        data = {
            "to_email": email,
            "subject": "VAPTFIX Signup OTP", 
            "body": body,
        }
        Util.send_mail(data)

   
   
   
    # ✅ ADMIN WELCOME EMAIL
    @staticmethod
    def send_admin_welcome_email(user_email):

        body = f"""
        Dear Administrator,

        Your administrator account for VAPTFIX has been successfully created.

        Once signed in, you will be able to complete your initial setup and begin managing the system.

        Thank you for choosing VAPTFIX.

        """

        data = {
            "to_email": user_email,
            "subject": "Your Admin Account Has Been Created",
            "body": body,
        }

        return Util.send_mail(data)

# Verify reCAPTCHA
def verify_recaptcha(recaptcha_response):
    """
    Verify reCAPTCHA response with Google's verification endpoint.
    Skips verification if DEBUG mode is active.
    """
    try:
        # Skip reCAPTCHA verification in DEBUG mode
        if settings.DEBUG:
            logger.debug("DEBUG mode active – skipping reCAPTCHA verification")
            return True, "reCAPTCHA verification skipped (DEBUG mode)"

        if not recaptcha_response:
            logger.warning("No reCAPTCHA response provided")
            return False, "reCAPTCHA verification is required"
        
        # Google reCAPTCHA verification URL
        url = "https://www.google.com/recaptcha/api/siteverify"
        
        # Data to send to Google
        data = {
            'secret': settings.RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        
        # Make request to Google's verification endpoint
        response = requests.post(url, data=data, timeout=10)
        result = response.json()
        
        logger.info(f"reCAPTCHA verification result: {result}")
        
        # Check if verification was successful
        if result.get('success'):
            return True, "reCAPTCHA verified successfully"
        else:
            error_codes = result.get('error-codes', [])
            logger.warning(f"reCAPTCHA verification failed. Error codes: {error_codes}")
            return False, "reCAPTCHA verification failed. Please try again."
            
    except requests.RequestException as e:
        logger.error(f"reCAPTCHA verification request error: {str(e)}")
        return False, "reCAPTCHA verification service unavailable"
    except Exception as e:
        logger.error(f"reCAPTCHA verification error: {str(e)}")
        return False, "reCAPTCHA verification failed"
    
    
class JiraTokenManager:
    """Manage Jira OAuth tokens stored in User model"""

    @staticmethod
    def save_token(user, access_token, refresh_token, expires_in, cloud_id, site_url, site_name, scopes):
        """Save or update Jira token for a user"""
        user.jira_access_token = access_token
        user.jira_refresh_token = refresh_token
        user.jira_token_expires_at = timezone.now() + timedelta(seconds=expires_in)
        user.jira_cloud_id = cloud_id
        user.jira_site_url = site_url
        user.jira_site_name = site_name
        user.jira_scopes = scopes
        user.save(update_fields=[
            'jira_access_token',
            'jira_refresh_token',
            'jira_token_expires_at',
            'jira_cloud_id',
            'jira_site_url',
            'jira_site_name',
            'jira_scopes'
        ])
        return user

    @staticmethod
    def get_token(user):
        """Get Jira token for a user"""
        return {
            'access_token': user.jira_access_token,
            'refresh_token': user.jira_refresh_token,
            'expires_at': user.jira_token_expires_at,
            'cloud_id': user.jira_cloud_id,
            'site_url': user.jira_site_url,
            'site_name': user.jira_site_name,
            'scopes': user.jira_scopes
        }

    @staticmethod
    def delete_token(user):
        """Delete Jira token for a user"""
        user.jira_access_token = None
        user.jira_refresh_token = None
        user.jira_token_expires_at = None
        user.jira_cloud_id = None
        user.jira_site_url = None
        user.jira_site_name = None
        user.jira_scopes = None
        user.save(update_fields=[
            'jira_access_token',
            'jira_refresh_token',
            'jira_token_expires_at',
            'jira_cloud_id',
            'jira_site_url',
            'jira_site_name',
            'jira_scopes'
        ])

    @staticmethod
    def is_token_expired(user):
        """Check if user's Jira token is expired"""
        if not user.jira_token_expires_at:
            return True
        return timezone.now() >= user.jira_token_expires_at