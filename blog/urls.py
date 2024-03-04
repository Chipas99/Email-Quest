from django.urls import path

from blog.apps import BlogConfig
from blog.views import BlogpostListView, BlogpostCreateView, BlogpostDetailView, BlogpostUpdateView, \
    BlogpostDeleteView

app_name = BlogConfig.name

urlpatterns = [
    path('', BlogpostListView.as_view(), name='post_list'),
    path('post_create/', BlogpostCreateView.as_view(), name='post_create'),
    path('post_view/<int:pk>/', BlogpostDetailView.as_view(), name='post_view'),
    path('post_update/<int:pk>/', BlogpostUpdateView.as_view(), name='post_update'),
    path('post_delete/<int:pk>/', BlogpostDeleteView.as_view(), name='post_delete'),
]
