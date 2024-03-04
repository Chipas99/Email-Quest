from django.conf import settings
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.auth.views import LoginView as BaseLoginView, PasswordChangeView, PasswordResetConfirmView
from django.contrib.auth.views import LogoutView as BaseLogoutView
from django.contrib.auth.views import PasswordResetView as BasePasswordResetCompleteView
from django.contrib.auth.views import PasswordResetView as BasePasswordResetDoneView
from django.contrib.auth.views import PasswordResetView as BasePasswordResetView
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.shortcuts import redirect
from django.urls import reverse_lazy, reverse
from django.views.generic import CreateView, TemplateView, ListView, UpdateView, DetailView, DeleteView

from Users.forms import LoginViewForm, UserRegisterForm, UserUpdateForm, UserPasswordForm, UserUpdateCustomForm
from Users.models import User


class LoginView(BaseLoginView):
    model = User
    form_class = LoginViewForm
    template_name = 'Users/login.html'
    extra_context = {
        'title': 'Вход пользователя',
        'phrases': ['фраза1', 'фраза2', 'фраза3'],
    }
    success_url = reverse_lazy('Users/home.html')


class LogoutView(BaseLogoutView):
    success_url = reverse_lazy('Users/login.html')


class RegisterView(CreateView):
    model = User
    form_class = UserRegisterForm
    template_name = 'Users/register.html'
    extra_context = {
        'title': 'Регистрация пользователя',
        'phrases': ['фраза1', 'фраза2', 'фраза3'],
    }

    def form_valid(self, form):
        password = User.objects.make_random_password()
        new_user = form.save(commit=False)
        new_user.is_active = False
        new_user.verification_code = password
        new_user.save()

        current_site = get_current_site(self.request)
        url = f'http://{current_site}/Users/email_verify/{new_user.verification_code}/'

        send_mail(
            recipient_list=[
                new_user.email],
            subject='Подтвердите ваш почтовый адрес',
            message=f'Для завершения регистрации на сайте перейдите по ссылке: {url}',
            from_email=settings.EMAIL_HOST_USER,
        )

        return super().form_valid(form)

    def get_success_url(self):
        return reverse('Users:verification_check') + \
            f'?email={self.object.email}'


class RegisterInfo(TemplateView):
    template_name = 'Users/verification_check.html'

    extra_context = {
        'title': 'Подтвердите регистрацию',
        'phrases': ['фраза1', 'фраза2', 'фраза3']
    }

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user_email = self.request.GET.get('email')
        context['info'] = f'На ваш почтовый адрес {user_email} была отправлена ссылка для завершения регистрации.'
        return context


class UserListView(ListView):
    model = User
    extra_context = {
        'title': 'Список пользователей сервиса',
        'phrases': ['фраза1', 'фраза2', 'фраза3']
    }


class UserUpdateVie(UpdateView):
    model = User
    form_class = UserUpdateForm

    extra_context = {
        'title': 'Редактирование пользователя',
        'phrases': ['фраза1', 'фраза2', 'фраза3']
    }

    def get_success_url(self):
        return reverse('Users:user_detail', args=[self.kwargs.get('pk')])


class UserCustomUpdateView(
        PermissionRequiredMixin,
        UpdateView):
    model = User
    form_class = UserUpdateCustomForm
    permission_required = 'Users.set_is_activated'

    extra_context = {
        'title': 'Редактирование пользователя',
        'phrases': ['фраза1', 'фраза2', 'фраза3']
    }

    def get_success_url(self):
        return reverse('Users:user_detail', args=[self.kwargs.get('pk')])


class UserDetailView(DetailView):
    model = User
    extra_context = {
        'title': 'Просмотр пользователя',
        'phrases': ['фраза1', 'фраза2', 'фраза3']
    }


class UserDeleteView(DeleteView):
    model = User
    success_url = reverse_lazy('Users:register')
    extra_context = {
        'title': 'Удаление пользователя',
        'phrases': ['фраза1', 'фраза2', 'фраза3']
    }


class UserPasswordChangeView(PasswordChangeView):
    form_class = UserPasswordForm
    template_name = 'Users/password_change.html'

    def get_object(self, queryset=None):
        return self.request.user

    def get_success_url(self):
        return reverse_lazy(
            'Users:user_update', kwargs={
                'pk': self.request.user.pk})


class PasswordResetView(BasePasswordResetView):
    template_name = 'Users/password_reset_form.html'
    email_template_name = 'Users/password_reset_email.html'
    from_email = settings.EMAIL_HOST_USER
    success_url = reverse_lazy('Users:password_reset_done')


class PasswordResetDoneView(BasePasswordResetDoneView):
    template_name = 'Users/password_reset_done.html'


class MyPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'Users/password_reset_confirm.html'
    success_url = reverse_lazy('Users:password_reset_complete')


class PasswordResetCompleteView(BasePasswordResetCompleteView):
    template_name = 'Users/password_reset_complete.html'
    success_url = reverse_lazy('Users:login')


def get_verification(request, verification_code):
    try:
        user = User.objects.filter(verification_code=verification_code).first()
        user.is_active = True
        user.save()
        return redirect('Users:verification_approve')
    except (AttributeError, ValidationError):
        return redirect('Users:verification_reject')
