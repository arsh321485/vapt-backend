from datetime import timedelta
import logging
import base64
import os
from time import timezone
import requests
import sendgrid
from sendgrid.helpers.mail import (
    Mail, Attachment, FileContent, FileName, FileType, Disposition, ContentId
)
from django.conf import settings
from users.models import User
import secrets
from django.core.cache import cache

logger = logging.getLogger(__name__)

class Util:
    @staticmethod
    def send_mail(data):
        """
        Send email using SendGrid API.
        Supports html_content if provided, else falls back to plain body.
        Returns (True, None) on success or (False, error_message) on failure.
        """
        try:
            sg = sendgrid.SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)
            html = data.get("html_content")
            if html:
                mail = Mail(
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to_emails=data["to_email"],
                    subject=data["subject"],
                    html_content=html,
                )
                # Attach inline logo if provided
                inline_logo = data.get("inline_logo_b64")
                if inline_logo:
                    attachment = Attachment(
                        FileContent(inline_logo),
                        FileName("logo.png"),
                        FileType("image/png"),
                        Disposition("inline"),
                        ContentId("vaptfix_logo"),
                    )
                    mail.add_attachment(attachment)
            else:
                mail = Mail(
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to_emails=data["to_email"],
                    subject=data["subject"],
                    plain_text_content=data["body"],
                )
            response = sg.send(mail)
            logger.info(f"SendGrid response: {response.status_code}")
            if response.status_code in [200, 201, 202]:
                return True, None
            error_msg = f"SendGrid returned status {response.status_code}: {response.body}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"SendGrid send error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        
        # ✅ ADMIN FIRST-TIME SIGNUP EMAIL
    # ADMIN OTP EMAIL (SIGNUP)
    @staticmethod
    def send_signup_otp(email, otp=None):
        if otp is None:
            otp = str(secrets.randbelow(900000) + 100000)

        # Cache OTP only (password stored separately)
        cache.set(f"signup_otp_{email}", otp, timeout=300)

        # Load logo (same approach as welcome email)
        logo_b64 = None
        logo_path = os.path.join(str(settings.BASE_DIR), "users", "static", "users", "logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                logo_b64 = base64.b64encode(f.read()).decode("utf-8")

        # Prefer CID image for better email client compatibility.
        if logo_b64:
            logo_html = '<img src="cid:vaptfix_logo" alt="VAPTFIX" style="height:42px; display:block; margin:0 auto;" />'
        else:
            logo_html = (
                '<div style="font-size:20px; color:#ffffff; font-weight:700; letter-spacing:0.5px;">'
                'VAPTFIX'
                '</div>'
            )

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="margin:0; padding:0; background-color:#eef0f6; font-family:Arial, sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#eef0f6; padding:36px 0;">
            <tr>
              <td align="center">
                <table width="480" cellpadding="0" cellspacing="0"
                       style="background:#ffffff; border-radius:22px; overflow:hidden;
                              box-shadow:0 12px 30px rgba(18, 22, 33, 0.10);">

                  <!-- Dark header with logo -->
                  <tr>
                    <td style="background-color:#23124d; padding:20px 30px; text-align:center;">
                      {logo_html}
                    </td>
                  </tr>

                  <!-- Body -->
                  <tr>
                    <td style="padding:34px 34px 20px 34px; text-align:center;">
                      <h1 style="color:#1f2040; margin:0; font-size:36px; line-height:1.05;">Admin Signup - OTP Verification</h1>
                      <p style="color:#545a6a; font-size:15px; line-height:1.6; margin:20px 0 18px 0;">
                        Your One-Time Password (OTP) for VAPTFIX Admin Signup is:
                      </p>

                      <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 auto 22px auto;">
                        <tr>
                          <td align="center">
                            <div style="display:inline-block; background:#f0f2f7; border-radius:10px; padding:16px 28px;
                                        font-size:54px; letter-spacing:10px; color:#1f2040; font-weight:700;">
                              {otp}
                            </div>
                          </td>
                        </tr>
                      </table>

                      <table width="100%" cellpadding="0" cellspacing="0"
                             style="background:#e5f8ff; border-radius:8px; margin:0 auto 12px auto;">
                        <tr>
                          <td style="padding:14px 14px; color:#2e3d4f; font-size:14px; line-height:1.6; text-align:left;">
                            This OTP is valid for <strong>5 minutes</strong>.
                        Please do not share this OTP with anyone for security reasons.
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>

                  <!-- Footer -->
                  <tr>
                    <td style="padding:18px 34px 24px 34px; text-align:center;">
                      <p style="color:#9a9dad; font-size:12px; letter-spacing:1.2px; margin:0;">
                        &copy; 2026 VAPTFIX. All rights reserved.
                      </p>
                    </td>
                  </tr>

                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        """

        data = {
            "to_email": email,
            "subject": "VAPTFIX Admin Signup – OTP Verification",
            "html_content": html_content,
            "inline_logo_b64": logo_b64,
        }
        success, error = Util.send_mail(data)
        return success, error

   
   
   
    # ✅ ADMIN WELCOME EMAIL
    @staticmethod
    def send_admin_welcome_email(user_email):
        # Try to load logo from static file for inline CID attachment
        logo_b64 = None
        logo_path = os.path.join(str(settings.BASE_DIR), "users", "static", "users", "logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                logo_b64 = base64.b64encode(f.read()).decode("utf-8")

        if logo_b64:
            logo_html = '<img src="cid:vaptfix_logo" alt="VAPTFIX" style="height:42px; display:block; margin:0 auto;" />'
        else:
            logo_html = (
                '<div style="font-size:20px; color:#ffffff; font-weight:700; letter-spacing:0.5px;">'
                'VAPTFIX'
                '</div>'
            )

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="margin:0; padding:0; background-color:#eef0f6; font-family:Arial, sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#eef0f6; padding:36px 0;">
            <tr>
              <td align="center">
                <table width="480" cellpadding="0" cellspacing="0"
                       style="background:#ffffff; border-radius:22px; overflow:hidden;
                              box-shadow:0 12px 30px rgba(18, 22, 33, 0.10);">

                  <!-- Header (same style as OTP mail) -->
                  <tr>
                    <td style="background-color:#23124d; padding:20px 30px; text-align:center;">
                      {logo_html}
                    </td>
                  </tr>

                  <!-- Body -->
                  <tr>
                    <td style="padding:34px 34px 20px 34px;">
                      <h1 style="color:#1f2040; margin:0 0 16px 0; font-size:36px; line-height:1.05; text-align:center;">
                        Administrator Account Created Successfully
                      </h1>

                      <p style="color:#444; font-size:15px; line-height:1.6;">
                        Dear Administrator,
                      </p>
                      <p style="color:#444; font-size:15px; line-height:1.6;">
                        We are pleased to inform you that your Administrator account for
                        VAPTFIX has been successfully created.
                        You may now sign in to the platform using your registered credentials.
                      </p>
                      <p style="color:#444; font-size:15px; line-height:1.6;">
                        Once logged in, you will be able to:
                      </p>
                      <ul style="color:#444; font-size:15px; line-height:2; padding-left:20px;">
                        <li>Complete your initial system configuration</li>
                        <li>Configure teams and user roles</li>
                        <li>Add and manage assets</li>
                        <li>Initiate vulnerability scans</li>
                        <li>Monitor security posture and remediation progress</li>
                      </ul>
                      <p style="color:#444; font-size:15px; line-height:1.6;">
                        We recommend completing the initial setup to ensure your environment
                        is properly configured for secure and efficient operations.
                      </p>
                    </td>
                  </tr>

                  <!-- Footer -->
                  <tr>
                    <td style="padding:18px 34px 24px 34px; text-align:center;">
                      <p style="color:#9a9dad; font-size:12px; letter-spacing:1.2px; margin:0;">
                        &copy; 2026 VAPTFIX. All rights reserved.
                      </p>
                    </td>
                  </tr>

                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        """

        data = {
            "to_email": user_email,
            "subject": "Administrator Account Created Successfully – VAPTFIX",
            "html_content": html_content,
            "inline_logo_b64": logo_b64,
        }

        return Util.send_mail(data)

    @staticmethod
    def _get_logo(base_dir):
        """Helper: load logo as base64 or return fallback HTML."""
        logo_b64 = None
        logo_path = os.path.join(str(base_dir), "users", "static", "users", "logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                logo_b64 = base64.b64encode(f.read()).decode("utf-8")
        if logo_b64:
            logo_html = f'<img src="data:image/png;base64,{logo_b64}" alt="VAPTFIX" style="height:60px;" />'
        else:
            logo_html = '<h2 style="color:#1a73e8; margin:0;">VAPTFIX</h2>'
        return logo_b64, logo_html

    @staticmethod
    def send_scoping_sales_email(project_detail, testing_methodologies):
        """Send scoping form details to sales team. testing_methodologies can be a list or single object."""
        logo_b64, logo_html = Util._get_logo(settings.BASE_DIR)

        def fmt_list(items):
            return ', '.join([i.replace('_', ' ').title() for i in items]) if items else '—'

        # Normalize to list
        if not isinstance(testing_methodologies, (list, tuple)):
            try:
                methodologies_list = list(testing_methodologies)
            except TypeError:
                methodologies_list = [testing_methodologies]
        else:
            methodologies_list = list(testing_methodologies)

        # Build one section per testing type
        methodology_sections = ""
        for m in methodologies_list:
            methodology_sections += f"""
                      <h3 style="color:#1a73e8; font-size:14px; margin:24px 0 10px 0; text-transform:uppercase; letter-spacing:1px;">
                        Testing Methodology — {m.testing_type.replace('_', ' ').title()}
                      </h3>
                      <table width="100%" cellpadding="8" cellspacing="0"
                             style="background:#f8f9fa; border-radius:6px; font-size:14px; color:#444; margin-bottom:12px;">
                        <tr><td style="width:40%; color:#888;">Assessment Categories</td><td>{fmt_list(m.assessment_categories)}</td></tr>
                        <tr><td style="color:#888;">Assessment Notes</td><td>{m.assessment_notes or '—'}</td></tr>
                        <tr><td style="color:#888;">Network Perspective</td><td>{m.get_network_perspective_display()}</td></tr>
                        <tr><td style="color:#888;">Environment</td><td>{m.get_environment_display()}</td></tr>
                        <tr><td style="color:#888;">Compliance Standards</td><td>{fmt_list(m.compliance_standards)}</td></tr>
                        <tr><td style="color:#888;">Compliance Notes</td><td>{m.compliance_notes or '—'}</td></tr>
                      </table>
            """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="margin:0; padding:0; background-color:#f4f6f8; font-family:Arial, sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f6f8; padding:40px 0;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0"
                       style="background:#ffffff; border-radius:8px; overflow:hidden;
                              box-shadow:0 2px 8px rgba(0,0,0,0.08);">

                  <!-- Header -->
                  <tr>
                    <td style="background-color:#ffffff; padding:30px 40px; text-align:center;
                                border-bottom:1px solid #e8eaed;">
                      {logo_html}
                    </td>
                  </tr>

                  <!-- Body -->
                  <tr>
                    <td style="padding:40px;">
                      <h2 style="color:#1a1a2e; margin:0 0 8px 0;">New Scoping Form Submission</h2>
                      <hr style="border:none; border-top:2px solid #1a73e8; margin:0 0 24px 0; width:60px; text-align:left;" />

                      <p style="color:#444; font-size:15px; line-height:1.6;">
                        A new scoping form has been submitted. Details below:
                      </p>

                      <!-- Project Details -->
                      <h3 style="color:#1a73e8; font-size:14px; margin:20px 0 10px 0; text-transform:uppercase; letter-spacing:1px;">
                        Project Details
                      </h3>
                      <table width="100%" cellpadding="8" cellspacing="0"
                             style="background:#f8f9fa; border-radius:6px; font-size:14px; color:#444;">
                        <tr><td style="width:40%; color:#888;">Admin Account</td><td><strong>{project_detail.admin.email}</strong></td></tr>
                        <tr><td style="color:#888;">Organization</td><td><strong>{project_detail.organization_name}</strong></td></tr>
                        <tr><td style="color:#888;">Industry</td><td>{project_detail.get_industry_display()}</td></tr>
                        <tr><td style="color:#888;">Country</td><td>{project_detail.country}</td></tr>
                        <tr><td style="color:#888;">Contact Name</td><td>{project_detail.full_name}</td></tr>
                        <tr><td style="color:#888;">Contact Email</td><td>{project_detail.email_address}</td></tr>
                        <tr><td style="color:#888;">Phone</td><td>{project_detail.phone_number or '—'}</td></tr>
                      </table>

                      {methodology_sections}
                    </td>
                  </tr>

                  <!-- Footer -->
                  <tr>
                    <td style="background-color:#f4f6f8; padding:20px 40px; text-align:center;">
                      <p style="color:#888; font-size:12px; margin:0;">
                        &copy; 2026 VAPTFIX. All rights reserved.
                      </p>
                    </td>
                  </tr>

                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        """

        data = {
            "to_email": "sales.secureitlab@gmail.com",
            "subject": f"New Scoping Form Submission — {project_detail.organization_name}",
            "html_content": html_content,
            "inline_logo_b64": logo_b64,
        }
        return Util.send_mail(data)

    @staticmethod
    def send_scoping_admin_confirmation_email(admin_email, org_name):
        """Send confirmation email to admin after scoping form submission."""
        logo_b64, _ = Util._get_logo(settings.BASE_DIR)
        if logo_b64:
            logo_html = '<img src="cid:vaptfix_logo" alt="VAPTFIX" style="height:42px; display:block; margin:0 auto;" />'
        else:
            logo_html = (
                '<div style="font-size:20px; color:#ffffff; font-weight:700; letter-spacing:0.5px;">'
                'VAPTFIX'
                '</div>'
            )

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="margin:0; padding:0; background-color:#eef0f6; font-family:Arial, sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#eef0f6; padding:36px 0;">
            <tr>
              <td align="center">
                <table width="480" cellpadding="0" cellspacing="0"
                       style="background:#ffffff; border-radius:22px; overflow:hidden;
                              box-shadow:0 12px 30px rgba(18, 22, 33, 0.10);">

                  <!-- Header (same style as OTP / welcome mail) -->
                  <tr>
                    <td style="background-color:#23124d; padding:20px 30px; text-align:center;">
                      {logo_html}
                    </td>
                  </tr>

                  <!-- Body -->
                  <tr>
                    <td style="padding:34px 34px 20px 34px; text-align:center;">
                      <h1 style="color:#1f2040; margin:0 0 16px 0; font-size:36px; line-height:1.05;">
                        Form Submitted Successfully!
                      </h1>

                      <p style="color:#444; font-size:15px; line-height:1.6;">
                        Thank you for completing the scoping form for <strong>{org_name}</strong>.
                      </p>
                      <p style="color:#444; font-size:15px; line-height:1.6;">
                        Our sales team will review your submission and contact you soon via email.
                      </p>

                    </td>
                  </tr>

                  <!-- Footer -->
                  <tr>
                    <td style="padding:18px 34px 24px 34px; text-align:center;">
                      <p style="color:#9a9dad; font-size:12px; letter-spacing:1.2px; margin:0;">
                        &copy; 2026 VAPTFIX. All rights reserved.
                      </p>
                    </td>
                  </tr>

                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        """

        data = {
            "to_email": admin_email,
            "subject": "Scoping Form Submitted Successfully — VAPTFIX",
            "html_content": html_content,
            "inline_logo_b64": logo_b64,
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