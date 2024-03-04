import random

from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin, UserPassesTestMixin
from django.http import Http404
from django.shortcuts import redirect
from django.urls import reverse_lazy, reverse
from django.views.generic import TemplateView, ListView, CreateView, UpdateView, DetailView, DeleteView

from blog.models import Blogpost
from mailing.forms import MailingSrvForm, MailForm, ClientForm, MailingSrvCustomForm
from mailing.models import MailingSrv, Mail, Client, Log
from mailing.services import manual_send_mailing
from Users.models import User


# Create your views here.

class OwnerSuperuserMixin:
    def get_object(self, queryset=None):
        self.object = super().get_object(queryset)
        if self.object.owner != self.request.user and not self.request.user.is_superuser:
            raise Http404
        return self.object


class BaseContextMixin:
    phrases = [
        "Почтовая рассылка: отправка сообщений и уведомлений по электронной почте.",
        "Автоматизация рассылок: возможность настроить автоматическую отправку сообщений по определенным событиям "
        "или расписанию.",
        "Управление подписчиками: возможность добавлять и удалять подписчиков, управлять списками рассылок и "
        "сегментировать аудиторию.",
        "Шаблоны и персонализация: создание и использование шаблонов для удобного оформления сообщений, "
        "а также возможность персонализации контента для каждого получателя."
        "Аналитика и отчетность: предоставление статистики о доставке, открытии и кликах в сообщениях, "
        "а также возможность создания отчетов для оценки эффективности рассылок."
        "Сегментация аудитории: возможность разделить аудиторию на группы и отправлять сообщения только "
        "определенным сегментам."
    ]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        random_phrase = random.choice(self.phrases)
        context['phrases'] = random_phrase
        return context


class MainPage(BaseContextMixin, TemplateView):
    template_name = 'mailing/home.html'

    extra_context = {
        'phrases': BaseContextMixin.phrases,
    }

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Главная страница сервеса рассылок'
        context['mailings_count'] = MailingSrv.objects.count()

        context['active_mailings_count'] = MailingSrv.objects.filter(is_activated=True).count()

        context['unique_clients_count'] = Client.objects.count()
        context['unique_users_count'] = User.objects.count()

        blogpost_list = list(Blogpost.objects.filter(is_published=True))
        random.shuffle(blogpost_list)
        context['blogpost_list'] = blogpost_list[:3]

        return context


class MailingSrvListView(LoginRequiredMixin, BaseContextMixin, ListView):
    model = MailingSrv
    login_url = 'users:login'
    extra_context = {
        'title': 'Список рассылок',
        'phrases': BaseContextMixin.phrases,
    }


class MailingSrvCreateView(BaseContextMixin, CreateView):
    model = MailingSrv
    form_class = MailingSrvForm

    extra_context = {
        'title': 'Создание новой рассылки',
        'phrases': BaseContextMixin.phrases,
    }

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update({'request': self.request})
        return kwargs

    def form_valid(self, form, *args, **kwargs):
        if form.is_valid():
            new_mailing = form.save(commit=False)
            new_mailing.owner = self.request.user
            new_mailing.save()
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('mailing:mailings_list')


class MailingSrvUpdateView(UserPassesTestMixin, BaseContextMixin, UpdateView):
    model = MailingSrv
    form_class = MailingSrvForm

    extra_context = {
        'title': 'Редактирование рассылки',
        'phrases': BaseContextMixin.phrases,
    }

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update({'request': self.request})
        return kwargs

    def get_success_url(self):
        return reverse('mailing:mailings_detail', args=[self.object.pk])

    def test_func(self):
        if self.request.user.is_staff:
            return True
        return self.request.user == MailingSrv.objects.get(pk=self.kwargs['pk']).owner


class MailingSrvCustomUpdateView(LoginRequiredMixin, PermissionRequiredMixin, BaseContextMixin, UpdateView):
    model = MailingSrv
    form_class = MailingSrvCustomForm
    permission_required = 'mailing.set_is_activated'

    extra_context = {
        'title': 'Редактирование рассылки',
        'phrases': BaseContextMixin.phrases,
    }

    def get_success_url(self):
        return reverse('mailing:mailings_detail', args=[self.object.pk])


class MailingSrvDetailView(BaseContextMixin, DetailView):
    model = MailingSrv

    extra_context = {
        'title': 'Детали рассылки',
        'phrases': BaseContextMixin.phrases,
    }

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        mailing_data = []
        recipients_data = self.object.recipients.values('email', 'initials', 'comment')
        mailing_data.append({'recipients_data': recipients_data})
        context['mailing_data'] = mailing_data

        mail_subject = None
        if self.object.mail:
            mail_subject = self.object.mail.subject

        context['mail_subject'] = mail_subject
        return context


class MailingSrvDeleteView(BaseContextMixin, DeleteView):
    model = MailingSrv
    success_url = reverse_lazy('mailing:mailings_list')

    extra_context = {
        'title': 'Удаление рассылки',
        'phrases': BaseContextMixin.phrases,
    }


class MailListView(LoginRequiredMixin, BaseContextMixin, ListView):
    model = Mail
    login_url = 'users:login'
    extra_context = {
        'title': 'Список писем',
        'phrases': BaseContextMixin.phrases,
    }

    def get_queryset(self, *args, **kwargs):
        queryset = super().get_queryset(*args, **kwargs)
        if self.request.user.is_superuser:
            queryset = Mail.objects.all()
        else:
            queryset = queryset.filter(owner=self.request.user)
        return queryset


class MailCreateView(BaseContextMixin, CreateView):
    model = Mail
    form_class = MailForm
    success_url = reverse_lazy('mailing:mail_list')
    extra_context = {
        'title': 'Создание письма',
        'phrases': BaseContextMixin.phrases,
    }

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update({'request': self.request})
        return kwargs

    def form_valid(self, form):
        new_mail = form.save()
        new_mail.owner = self.request.user
        new_mail.save()
        return super().form_valid(form)


class MailUpdateView(OwnerSuperuserMixin, BaseContextMixin, UpdateView):
    model = Mail
    form_class = MailForm
    extra_context = {
        'title': 'Редактирование письма',
        'phrases': BaseContextMixin.phrases,
    }

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update({'request': self.request})
        return kwargs

    def get_success_url(self):
        return reverse('mailing:mail_detail', args=[self.kwargs.get('pk')])


class MailDetailView(OwnerSuperuserMixin, BaseContextMixin, DetailView):
    model = Mail
    extra_context = {
        'title': 'Просмотр письма',
        'phrases': BaseContextMixin.phrases,
    }


class MailDeleteView(OwnerSuperuserMixin, BaseContextMixin, DeleteView):
    model = Mail
    success_url = reverse_lazy('mailing:mail_list')
    extra_context = {
        'title': 'Удаление письма',
        'phrases': BaseContextMixin.phrases,
    }


class ClientListView(LoginRequiredMixin, BaseContextMixin, ListView):
    model = Client
    login_url = 'users:login'
    extra_context = {
        'title': 'Список клиентов',
        'phrases': BaseContextMixin.phrases,
    }

    def get_queryset(self, *args, **kwargs):
        queryset = super().get_queryset(*args, **kwargs)
        if self.request.user.is_superuser:
            queryset = Client.objects.all()
        else:
            queryset = queryset.filter(owner=self.request.user)
        return queryset


class ClientCreateView(BaseContextMixin, CreateView):
    model = Client
    form_class = ClientForm
    success_url = reverse_lazy('mailing:client_list')
    extra_context = {
        'title': 'Добавить клиента',
        'phrases': BaseContextMixin.phrases,
    }

    def form_valid(self, form):
        new_client = form.save()
        new_client.owner = self.request.user
        new_client.save()
        return super().form_valid(form)


class ClientUpdateView(OwnerSuperuserMixin, BaseContextMixin, UpdateView):
    model = Client
    form_class = ClientForm
    extra_context = {
        'title': 'Редактирование клиента',
        'phrases': BaseContextMixin.phrases,
    }

    def get_success_url(self):
        return reverse('mailing:client_detail', args=[self.kwargs.get('pk')])


class ClientDetailView(OwnerSuperuserMixin, BaseContextMixin, DetailView):
    model = Client
    extra_context = {
        'title': 'Просмотр клиента',
        'phrases': BaseContextMixin.phrases,
    }


class ClientDeleteView(OwnerSuperuserMixin, BaseContextMixin, DeleteView):
    model = Client
    success_url = reverse_lazy('mailing:client_list')
    extra_context = {
        'title': 'Удаление клиента',
        'phrases': BaseContextMixin.phrases,
    }


class LogListView(LoginRequiredMixin, BaseContextMixin, ListView):
    model = Log
    login_url = 'users:login'
    extra_context = {
        'title': 'Отчеты по рассылкам',
        'phrases': BaseContextMixin.phrases,
    }

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.request.user.is_superuser:
            queryset = Log.objects.all()
        else:
            queryset = queryset.filter(mailing__owner=self.request.user)
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        mailing_data = []
        for log in context['object_list']:
            recipients_data = log.mailing.recipients.values('email', 'initials', 'comment')
            mailing_data.append({'log': log, 'recipients_data': recipients_data})
        context['mailing_data'] = mailing_data
        return context


class LogDetailView(BaseContextMixin, DetailView):
    model = Log
    extra_context = {
        'title': 'Отчет по рассылке',
        'phrases': BaseContextMixin.phrases,
    }

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        mailing_data = []
        recipients_data = self.object.mailing.recipients.values('email', 'initials', 'comment')
        mailing_data.append({'log': self.object, 'recipients_data': recipients_data})
        context['mailing_data'] = mailing_data
        return context


class LogDeleteView(BaseContextMixin, DeleteView):
    model = Log
    success_url = reverse_lazy('mailing:log_list')
    extra_context = {
        'title': 'Удаление отчета',
        'phrases': BaseContextMixin.phrases,
    }


def send_mailing_btn(request, pk):
    print(f'send_mailing {pk}')
    manual_send_mailing(pk)
    return redirect('mailing:mailings_list')
