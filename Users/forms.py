from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, UserChangeForm

from Users.models import User


class StyleFormMiXin(forms.Form):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if field_name != 'is_active':
                field.widget.attrs['class'] = 'form-control'


class LoginViewForm(StyleFormMiXin, AuthenticationForm):

    class Meta:
        model = User
        fields = '__all__'


class UserRegisterForm(StyleFormMiXin, UserCreationForm):

    class Meta:
        model = User
        fields = ('email', 'password1', 'password2',)


class UserUpdateForm(StyleFormMiXin, UserChangeForm):
    class Meta:
        model = User
        fields = (
            'email',
            'first_name',
            'last_name',
            'phone',
            'avatar',
            'password')
        widgets = {
            'password': forms.HiddenInput(),
        }

    password = forms.CharField(
        label='reset',
        max_length=256,
        widget=forms.HiddenInput())


class UserUpdateCustomForm(StyleFormMiXin, UserChangeForm):
    class Meta:
        model = User
        fields = ('is_active',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['password'].widget = forms.HiddenInput()


class UserPasswordForm(StyleFormMiXin, forms.Form):
    old_password = forms.CharField(
        widget=forms.PasswordInput,
        label='Старый пароль')
    new_password1 = forms.CharField(
        widget=forms.PasswordInput,
        label='Новый пароль')
    new_password2 = forms.CharField(
        widget=forms.PasswordInput,
        label='Подтверждение нового пароля')

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')

        if new_password1 and new_password2 and new_password1 != new_password2:
            raise forms.ValidationError('пароли не совпадают')

        return cleaned_data

    def save(self, commit=True):
        password = self.cleaned_data.get('new_password1')
        self.user.set_password(password)
        if commit:
            self.user.save()
        return self.user
