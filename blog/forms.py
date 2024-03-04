from django import forms

from blog.models import Blogpost


class StyleFormMixin(forms.Form):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if field_name != 'is_published':
                field.widget.attrs['class'] = 'form-control'


class BlogpostForm(StyleFormMixin, forms.ModelForm):
    class Meta:
        model = Blogpost
        fields = ('title', 'content', 'preview', 'is_published',)
