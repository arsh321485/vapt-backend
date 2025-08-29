import logging
from django.conf import settings
import sendgrid
from sendgrid.helpers.mail import Mail

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
