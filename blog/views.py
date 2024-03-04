from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import render, redirect
from django.urls import reverse_lazy, reverse
from django.views.generic import ListView, CreateView, UpdateView, DetailView, DeleteView

from blog.forms import BlogpostForm
from blog.models import Blogpost
from blog.services import get_cache_blogposts
from mailing.views import BaseContextMixin


class BlogpostListView(BaseContextMixin, ListView):
    model = Blogpost
    extra_context = {
        'title': 'Публикации'
    }

    def get_queryset(self):
        queryset = super().get_queryset()
        if not self.request.user.is_staff and not self.request.user.is_superuser:
            queryset = queryset.filter(is_published=True)
        return queryset

    def get_context_data(self, *args, **kwargs):
        context_data = super().get_context_data(*args, **kwargs)
        context_data['object_list'] = get_cache_blogposts()

        return context_data


class BlogpostCreateView(
        PermissionRequiredMixin,
        BaseContextMixin,
        CreateView):
    model = Blogpost
    form_class = BlogpostForm
    success_url = reverse_lazy('blog:post_list')
    permission_required = 'blog.add_blogpost'

    extra_context = {
        'title': 'Создание публикации'
    }

    def handle_no_permission(self):
        return redirect('mailing:access_denied')


class BlogpostDetailView(BaseContextMixin, DetailView):
    model = Blogpost
    extra_context = {
        'title': 'Публикация'
    }

    def get_object(self, queryset=None):
        self.object = super().get_object(queryset)
        self.object.views_count += 1
        self.object.save()

        return self.object


class BlogpostUpdateView(
        PermissionRequiredMixin,
        BaseContextMixin,
        UpdateView):
    model = Blogpost
    form_class = BlogpostForm
    permission_required = 'blog.change_blogpost'

    extra_context = {
        'title': 'Редакция публикации'
    }

    def get_success_url(self):
        return reverse('blog:post_view', args=[self.object.pk])

    def handle_no_permission(self):
        return redirect('mailing:access_denied')


class BlogpostDeleteView(
        PermissionRequiredMixin,
        BaseContextMixin,
        DeleteView):
    model = Blogpost
    success_url = reverse_lazy('blog:post_list')
    permission_required = 'blog.delete_blogpost'

    extra_context = {
        'title': 'Удаление публикации'
    }

    def handle_no_permission(self):
        return redirect('mailing:access_denied')


def custom_permission_denied(request):
    context = {
        'logged_in_user_email': request.user.email if request.user.is_authenticated else None
    }
    return render(request, 'mailing/access_denied.html', context=context)
