from datetime import timedelta

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from mailing.models import MailingSrv, Log


def my_job():
    day = timedelta(days=1)
    week = timedelta(weeks=1)

    now = timezone.now()

    mailings = MailingSrv.objects.filter(
        status='создана',
        is_activated=True,
        next__lte=now,
        finish__gte=now
    )

    for mailing in mailings:
        mailing.status = 'запущена'
        mailing.save()

        emails_list = mailing.recipients.values_list('email', flat=True)

        result = send_mail(
            subject=mailing.mail.subject,
            message=mailing.mail.content,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=emails_list,
            fail_silently=False,
        )

        if result == 1:
            status = 'успешно отправлено'
            server_response = '200'
        else:
            status = 'ошибка отправления'
            server_response = '400'

        log = Log.objects.create(
            mailing=mailing,
            status=status,
            server_response=server_response
        )

        if mailing.frequency == 'раз в день':
            mailing.next = log.attempt_time + day
        elif mailing.frequency == 'раз в неделю':
            mailing.next = log.attempt_time + week
        elif mailing.frequency == 'раз в месяц':
            mailing.next = log.attempt_time + relativedelta(months=1)
        elif mailing.frequency == 'единоразово':
            mailing.next = mailing.finish

        if mailing.next < mailing.finish:
            mailing.status = 'создана'
        else:
            mailing.status = 'завершена'
        mailing.save()


def manual_send_mailing(pk):
    day = timedelta(days=1)
    week = timedelta(weeks=1)

    mailing = MailingSrv.objects.get(pk=pk)
    mailing.status = 'запущена'
    mailing.save()

    mailing_list = list(mailing.recipients.values_list('email', flat=True))
    subject = mailing.mail.subject
    message = mailing.mail.content

    result = send_mail(
        subject=subject,
        message=message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=mailing_list,
        fail_silently=False,
    )

    if result == 1:
        status = 'успешно отправлено'
        server_response = '200'
    else:
        status = 'ошибка отправления'
        server_response = '400'

    log = Log.objects.create(
        mailing=mailing,
        status=status,
        server_response=server_response
    )

    if mailing.frequency == 'раз в день':
        mailing.next = log.attempt_time + day
    elif mailing.frequency == 'раз в неделю':
        mailing.next = log.attempt_time + week
    elif mailing.frequency == 'раз в месяц':
        mailing.next = log.attempt_time + relativedelta(months=1)
    elif mailing.frequency == 'единоразово':
        mailing.next = mailing.finish

    if mailing.next < mailing.finish:
        mailing.status = 'создана'
    else:
        mailing.status = 'завершена'
    mailing.save()
