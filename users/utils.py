import logging
import requests
import sendgrid
from sendgrid.helpers.mail import Mail
from django.conf import settings

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
    
