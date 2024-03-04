from django import forms
from django.forms import DateTimeInput

from mailing.models import MailingSrv, Mail, Client


class StyleFormMiXin:

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if field_name != 'is_activated' and field_name != 'is_published':
                field.widget.attrs['class'] = 'form-control'


class MailingSrvForm(StyleFormMiXin, forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request')
        user = self.request.user
        super().__init__(*args, **kwargs)
        self.fields['recipients'].queryset = Client.objects.filter(owner=user)
        self.fields['mail'].queryset = Mail.objects.filter(owner=user)

    start = forms.DateTimeField(
        label='Время старта рассылки',
        required=False,
        widget=DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}, format='%Y-%m-%dT%H:%M')
    )

    finish = forms.DateTimeField(
        label='Время окончания рассылки',
        required=False,
        widget=DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}, format='%Y-%m-%dT%H:%M')
    )

    class Meta:
        model = MailingSrv
        exclude = ('next', 'owner', 'is_activated',)


class MailingSrvCustomForm(StyleFormMiXin, forms.ModelForm):

    class Meta:
        model = MailingSrv
        fields = ('is_activated',)


class MailForm(StyleFormMiXin, forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request')
        user = self.request.user
        super().__init__(*args, **kwargs)
        self.fields['mailings'].queryset = MailingSrv.objects.filter(owner=user)

    class Meta:
        model = Mail
        exclude = ('owner',)


class ClientForm(StyleFormMiXin, forms.ModelForm):
    class Meta:
        model = Client
        exclude = ('owner',)
