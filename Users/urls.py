from django.urls import path
from django.views.generic import TemplateView

from Users.apps import UsersConfig
from Users.views import LoginView, LogoutView, RegisterView, get_verification, RegisterInfo, UserListView, \
    UserUpdateView, UserDetailView, UserDeleteView, PasswordResetView, UserPasswordChangeView, PasswordResetDoneView, \
    PasswordResetCompleteView, MyPasswordResetConfirmView, UserCustomUpdateView

app_name = UsersConfig.name

urlpatterns = [
    path('', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('register/', RegisterView.as_view(), name='register'),
    path('verification_check/', RegisterInfo.as_view(), name='verification_check'),
    path('email_verify/<str:verification_code>/', get_verification, name='verification'),
    path('verification_approve/', TemplateView.as_view(
        template_name='Users/verification_approve.html'),
        name='verification_approve'),
    path('verification_reject/', TemplateView.as_view(
        template_name='Users/verification_reject.html'),
        name='verification_reject'),
    path('user_list/', UserListView.as_view(), name='user_list'),
    path('user_update/<int:pk>/', UserUpdateView.as_view(), name='user_update'),
    path('user_custom_update/<int:pk>/', UserCustomUpdateView.as_view(), name='user_custom_update'),
    path('user_detail/<int:pk>/', UserDetailView.as_view(), name='user_detail'),
    path('user_delete/<int:pk>/', UserDeleteView.as_view(), name='user_delete'),

    path('password_change/', UserPasswordChangeView.as_view(), name='password_change'),
    path('password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', MyPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', PasswordResetCompleteView.as_view(), name='password_reset_complete'),
]
