from django.contrib import admin

from blog.models import Blogpost


# Register your models here.

@admin.register(Blogpost)
class AdminBlogpost(admin.ModelAdmin):
    list_display = (
        'title',
        'content',
        'preview',
        'views_count',
        'date_create',
        'is_published',
    )
