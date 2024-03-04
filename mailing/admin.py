from django.contrib import admin

from mailing.models import Client, MailingSrv, Mail, Log


@admin.register(Client)
class AdminClient(admin.ModelAdmin):
    list_display = ('email', 'initials', 'comment',)


@admin.register(MailingSrv)
class AdminMailingSrv(admin.ModelAdmin):
    list_display = ('start', 'finish', 'status', 'frequency',)


@admin.register(Mail)
class AdminMail(admin.ModelAdmin):
    list_display = ('subject', 'content',)


@admin.register(Log)
class AdminLog(admin.ModelAdmin):
    list_display = ('attempt_time', 'status', 'server_response', 'mailing',)
