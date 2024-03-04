from django.urls import path
from django.views.decorators.cache import cache_page

from blog.views import custom_permission_denied
from mailing.apps import MailingConfig
from mailing.views import MainPage, MailingSrvListView, MailingSrvCreateView, MailingSrvUpdateView, \
    MailingSrvDetailView, MailingSrvDeleteView, MailListView, MailCreateView, MailUpdateView, MailDetailView, \
    MailDeleteView, ClientListView, ClientCreateView, ClientUpdateView, ClientDetailView, ClientDeleteView, \
    LogListView, LogDetailView, LogDeleteView, send_mailing_btn, MailingSrvCustomUpdateView

app_name = MailingConfig.name

urlpatterns = [
    path('', cache_page(60)(MainPage.as_view()), name='home'),
    path('mailings_list/', MailingSrvListView.as_view(), name='mailings_list'),
    path('mailings_create/', MailingSrvCreateView.as_view(), name='mailings_create'),
    path('mailings_update/<int:pk>/', MailingSrvUpdateView.as_view(), name='mailings_update'),
    path('mailings_custom_update/<int:pk>/', MailingSrvCustomUpdateView.as_view(), name='mailings_custom_update'),
    path('mailings_detail/<int:pk>/', MailingSrvDetailView.as_view(), name='mailings_detail'),
    path('mailings_delete/<int:pk>/', MailingSrvDeleteView.as_view(), name='mailings_delete'),
    path('<int:pk>/', send_mailing_btn, name='send_mailing_btn'),
    path('mail_list/', MailListView.as_view(), name='mail_list'),
    path('mail_create/', MailCreateView.as_view(), name='mail_create'),
    path('mail_update/<int:pk>/', MailUpdateView.as_view(), name='mail_update'),
    path('mail_detail/<int:pk>/', MailDetailView.as_view(), name='mail_detail'),
    path('mail_delete/<int:pk>/', MailDeleteView.as_view(), name='mail_delete'),
    path('client_list/', ClientListView.as_view(), name='client_list'),
    path('client_create/', ClientCreateView.as_view(), name='client_create'),
    path('client_update/<int:pk>/', ClientUpdateView.as_view(), name='client_update'),
    path('client_detail/<int:pk>/', ClientDetailView.as_view(), name='client_detail'),
    path('client_delete/<int:pk>/', ClientDeleteView.as_view(), name='client_delete'),
    path('log_list/', LogListView.as_view(), name='log_list'),
    path('log_detail/<int:pk>/', LogDetailView.as_view(), name='log_detail'),
    path('log_delete/<int:pk>/', LogDeleteView.as_view(), name='log_delete'),
    path('access_denied/', custom_permission_denied, name='access_denied'),
]
