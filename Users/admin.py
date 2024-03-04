from django.contrib import admin

from Users.models import User


# Register your models here.
@admin.register(User)
class AdminUser(admin.ModelAdmin):
    list_display = (
        'first_name',
        'last_name',
        'email',
        'phone',
        'avatar',
        'verification_code',
        'is_active',
    )
