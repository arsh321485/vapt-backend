from .renderers import UserRenderer
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    UserRegistrationView,
    UserLoginView,
    UserProfileView,
    UserProfileUpdateView,
    ChangePasswordView,
    SendPasswordResetEmailView,
    UserPasswordResetView,
    logout_view,
    SetPasswordView,
)

app_name = 'users'

urlpatterns = [
    # Authentication
    path('signup/', UserRegistrationView.as_view(), name='signup'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    
    # Profile Management
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('profile/update/', UserProfileUpdateView.as_view(), name='profile-update'),
    
    # Password Management
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('forgot-password/', SendPasswordResetEmailView.as_view(), name='forgot-password'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    path("set-password/", SetPasswordView.as_view(), name="set-password"),
    
    # Token Management
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
]