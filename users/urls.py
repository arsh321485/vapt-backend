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
    MicrosoftTeamsOAuthUrlView,
    MicrosoftTeamsCallbackView,
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
    SlackUserLoginView,
    SlackInviteUserView,
    JiraOAuthUrlView,
    JiraOAuthCallbackView,
    JiraOAuthView,
    JiraValidateTokenView,
    JiraGetUserView,
    JiraGetResourcesView,
    JiraAddCommentView,
    JiraCreateIssueView, 
    JiraGetIssueView, 
    JiraUpdateIssueView,
    JiraDeleteIssueView,  
    JiraSearchIssuesView,
    JiraAssignIssueView,
    JiraListProjectsView,
    JiraCreateProjectView
    # JiraGetProjectView,
    # JiraUpdateProjectView,
    # JiraDeleteProjectView,
)

app_name = 'users'

urlpatterns = [
    # Authentication
    path('signup/', UserRegistrationView.as_view(), name='signup'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('google-oauth/', GoogleOAuthView.as_view(), name='google-oauth'),
    # path('microsoft-teams-oauth/', MicrosoftTeamsOAuthView.as_view(), name='microsoft-teams-oauth'),
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
    path('microsoft-teams/oauth-url/', MicrosoftTeamsOAuthUrlView.as_view(), name='microsoft-teams-oauth-url'),
    path('microsoft-teams/callback/', MicrosoftTeamsCallbackView.as_view(), name='microsoft-teams-callback'),
    path('microsoft-teams-oauth/', MicrosoftTeamsOAuthView.as_view(), name='microsoft-teams-oauth'), #login
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
    
    
    path('jira/oauth-url/', JiraOAuthUrlView.as_view(), name='jira-oauth-url'),
    path('jira/callback/', JiraOAuthCallbackView.as_view(), name='jira-callback'),
    path('jira/oauth/', JiraOAuthView.as_view(), name='jira-oauth'),
    path('jira/validate-token/', JiraValidateTokenView.as_view(), name='jira-validate-token'),
    path('jira/user/', JiraGetUserView.as_view(), name='jira-get-user'),
    path('jira/resources/', JiraGetResourcesView.as_view(), name='jira-resources'),
    path('jira/projects/', JiraListProjectsView.as_view(), name='jira-list-projects'),
    path('jira/issues/comment/', JiraAddCommentView.as_view(), name='jira-add-comment'),
    
    path('jira/issues/create/', JiraCreateIssueView.as_view()),
    path('jira/issues/<str:issue_key>/', JiraGetIssueView.as_view()),
    path('jira/issues/<str:issue_key>/update/', JiraUpdateIssueView.as_view()),
    path('jira/issues/<str:issue_key>/delete/', JiraDeleteIssueView.as_view()),
    path('jira/issues/search/', JiraSearchIssuesView.as_view()),
    path('jira/issues/<str:issue_key>/assign/', JiraAssignIssueView.as_view()),
    
    path('jira/projects/', JiraListProjectsView.as_view(), name='jira_list_projects'),
    path('jira/projects/create/', JiraCreateProjectView.as_view(), name='jira_create_project'),
    # path('jira/projects/<str:project_key>/', JiraGetProjectView.as_view(), name='jira_get_project'),
    # path('jira/projects/<str:project_key>/update/', JiraUpdateProjectView.as_view(), name='jira_update_project'),
    # path('jira/projects/<str:project_key>/delete/', JiraDeleteProjectView.as_view(), name='jira_delete_project'),
]

