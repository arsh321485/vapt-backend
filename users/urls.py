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
    GoogleOAuthView,
    MicrosoftTeamsOAuthView, 
    CreateTeamsChannelView,
    SendTeamsMessageView,
    ListTeamsView,
    ListChannelsView,
    CreateTeamView,
    AddUserToChannelView,
    UpdateTeamView,
    DeleteTeamView,
    UpdateChannelView,
    DeleteChannelView,
    SlackOAuthUrlView,
    SlackOAuthView,
    SendSlackMessageView,
    CreateSlackChannelView,
    ListSlackChannelsView,
    # SendInteractiveSlackMessageView,
    SlackOAuthCallbackView,
    slack_oauth_url,
    SlackUserLoginView,
    SlackValidateTokenView,
    UpdateSlackChannelView,
    DeleteSlackChannelView,
    JoinSlackChannelView,
    AddUserToSlackChannelView,
    SlackUserListView,
    SlackInviteUserView,
)

app_name = 'users'

urlpatterns = [
    # Authentication
    path('signup/', UserRegistrationView.as_view(), name='signup'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('google-oauth/', GoogleOAuthView.as_view(), name='google-oauth'),
    path('microsoft-teams-oauth/', MicrosoftTeamsOAuthView.as_view(), name='microsoft-teams-oauth'),  # Add this line
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
    
    
    # Microsoft  APIs    
    path('teams/create/', CreateTeamView.as_view(), name='create-team'),
    path('teams/update/', UpdateTeamView.as_view(), name='update-team'),              
    path('teams/delete/', DeleteTeamView.as_view(), name='delete-team'),              
    path('teams/list/', ListTeamsView.as_view(), name='list-teams'),
    
    path('teams/channels/list/', ListChannelsView.as_view(), name='list-channels'),
    path('teams/channels/create/', CreateTeamsChannelView.as_view(), name='create-channel'),
    path('teams/channels/update/', UpdateChannelView.as_view(), name='update-channel'),  
    path('teams/channels/delete/', DeleteChannelView.as_view(), name='delete-channel'),  
    path('teams/channels/add-user/', AddUserToChannelView.as_view(), name='add-user-to-channel'),
    
    path('teams/messages/send/', SendTeamsMessageView.as_view(), name='send-message'),
    
    
    # Slack APIs 
    path('slack/oauth-url/', SlackOAuthUrlView.as_view(), name='slack-oauth-url'),
    path('slack/callback/', SlackOAuthCallbackView.as_view(), name='slack-callback'),
    path('slack-oauth/', SlackOAuthView.as_view(), name='slack-oauth'),
    
    path('slack/login/', SlackUserLoginView.as_view(), name='slack-login'),
    path('slack/validate-token/', SlackValidateTokenView.as_view(), name='slack-validate-token'),
    
    # Slack Channel Management
    path('slack/channels/list/', ListSlackChannelsView.as_view(), name='slack-list-channels'),
    path('slack/channels/create/', CreateSlackChannelView.as_view(), name='slack-create-channel'),
    path('slack/channels/update/', UpdateSlackChannelView.as_view(), name='slack-update-channel'),
    path('slack/channels/delete/', DeleteSlackChannelView.as_view(), name='slack-delete-channel'),
    
    # Slack Messaging
    path('slack/messages/send/', SendSlackMessageView.as_view(), name='slack-send-message'),
    path('slack/channel/join/', JoinSlackChannelView.as_view(), name='slack-join-channel'),
    
    path('slack/channel/add-user/', AddUserToSlackChannelView.as_view(), name='slack-add-user'),
    path("slack/users/list/", SlackUserListView.as_view(), name="slack-users-list"),
    path("slack/channel/invite/", SlackInviteUserView.as_view(), name="slack-invite-user"),
]