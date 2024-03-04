from django.db import models

# Create your models here.

NULLABLE = {
    'null': True,
    'blank': True,
}


class Blogpost(models.Model):
    """
    Модель для хранения информации о публикациях в блоге.
    """
    title = models.CharField(max_length=150, verbose_name='заголовок')
    content = models.TextField(verbose_name='содержимое', **NULLABLE)
    preview = models.ImageField(upload_to='blog/', verbose_name='изображение', **NULLABLE)
    views_count = models.IntegerField(default=0, verbose_name='просмотры')
    date_create = models.DateTimeField(auto_now_add=True, verbose_name='дата публикации')
    is_published = models.BooleanField(default=True, verbose_name='опубликовано')

    def __str__(self):
        return f'Публикация: {self.title}'

    class Meta:
        verbose_name = 'публикация'
        verbose_name_plural = "публикации"
        ordering = ("-date_create",)
