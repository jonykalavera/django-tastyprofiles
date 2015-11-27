# coding: utf-8
import datetime

from django import forms
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import (
    UserCreationForm as AuthUserCreationForm,
    UserChangeForm as AuthUserChangeForm,
    PasswordResetForm, PasswordChangeForm,
    SetPasswordForm
)
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.models import get_current_site
from django.utils.http import int_to_base36
from django.template import loader
from django.utils.translation import ugettext as _

from captcha.fields import ReCaptchaField

User = get_user_model()


class BaseUserForm(forms.ModelForm):
    username = forms.CharField(required=False)  # to support patch
    email = forms.EmailField(required=False)  # to support patch
    repeat_password = forms.CharField(
        label=_('Password confirm'),
        widget=forms.PasswordInput,
        help_text=_('Insert the same password to confirm'),
        required=False
    )

    class Meta:
        model = User
        exclude = [
            'id', 'access_token', 'facebook_open_graph', 'new_token_required',
            'date_joined', 'last_login'
        ]
        widgets = {
            'password': forms.PasswordInput(),
        }

    def save(self, commit=True):
        cache.clear()
        return super(BaseUserForm, self).save(commit=False)

    def clean_username(self):
        username = self.cleaned_data.get("username")
        if username and not self.instance:
            try:
                User.objects.get(username=username)
            except User.DoesNotExist:
                return username
            raise forms.ValidationError(_('Username already taken'))
        # assert False, username
        if not username and self.instance.pk is None:
            email = self.cleaned_data.get('email')
            if not email:
                raise forms.ValidationError(_('This field is mandatory'))
            username = hashlib.md5(email).hexdigest()
        return username

    def clean_password(self):
        password = self.cleaned_data.get("password")
        if len(password) < 6 and self.instance.pk is None:
            raise forms.ValidationError(_('Insert minimum six characters'))
        return password

    def clean_repeat_password(self):
        password = self.cleaned_data.get("password")
        repeat_password = self.cleaned_data.get("repeat_password")

        if repeat_password and len(repeat_password) < 6:
            raise forms.ValidationError(_('Insert minimum six characters'))
        if repeat_password and password != repeat_password:
            raise forms.ValidationError(
                self.ERROR_MESSAGES['PASSWORD_MISMATCH'])
        # assert False, not repeat_password
        if not repeat_password and self.instance.pk is None:
            raise forms.ValidationError(_('This field is mandatory'))
        return repeat_password

    def clean_email(self):
        email = self.cleaned_data["email"]
        if self.instance.pk:
            # Update
            # assert False, self.cleaned_data.keys()
            if "email" in self.cleaned_data.keys() and not email:
                raise forms.ValidationError(_('This field is mandatory'))
            if email and email != self.instance.email:
                try:
                    User.objects.get(email=email)
                except User.DoesNotExist:
                    return email
                raise forms.ValidationError(_('Email address already taken'))
        else:
            if not email:
                raise forms.ValidationError(_('This field is mandatory'))
            if email:
                try:
                    User.objects.get(email=email)
                except User.DoesNotExist:
                    return email
                raise forms.ValidationError(_('Email address already taken'))
        if not email and self.instance.pk is None:
            raise forms.ValidationError(_('This field is mandatory'))
        return email

    def clean_last_name(self):
        last_name = self.cleaned_data.get("last_name")
        # if not last_name:
        #     raise forms.ValidationError(_('This field is mandatory'))
        if last_name and len(last_name) < 3:
            raise forms.ValidationError(_('Insert minimum three characters'))

        return last_name

    def clean_first_name(self):
        first_name = self.cleaned_data.get("first_name")
        # if not first_name:
        #     raise forms.ValidationError(_('This field is mandatory'))
        if first_name and len(first_name) < 3:
            raise forms.ValidationError(_('Insert minimum three characters'))

        return first_name


class UserForm(BaseUserForm):
    """
    New User Form
    """
    captcha = ReCaptchaField()

    def clean_accept(self):
        accept = self.cleaned_data.get('accept')

        if not accept and self.instance.pk is None:
            raise forms.ValidationError(_('This field is mandatory'))
        return accept


class UpdateUserForm(BaseUserForm):
    """
    Update existing user Form.
    """
    # def clean_last_name(self):
    #     last_name = self.cleaned_data.get("last_name")
    #     if last_name and len(last_name) < 3:
    #         raise forms.ValidationError(_('Insert minimum three characters'))

    #     return last_name

    # def clean_first_name(self):
    #     first_name = self.cleaned_data.get("first_name")
    #     if first_name and len(first_name) < 3:
    #         raise forms.ValidationError(_('Insert minimum three characters'))

    #     return first_name
    class Meta(BaseUserForm.Meta):
        """
        Meta options
        """
            


class CustomPasswordResetForm(PasswordResetForm):
    """
    Customizations for default Password Reset Form.
    """
    def get_users(self, email):
        users = super(CustomPasswordResetForm, self).get_users(email)

        active_users = [user for user in users]

        if len(active_users) == 0:
            raise forms.ValidationError(
                _('User does not have an usable password'))

        return active_users


class CustomPasswordChangeForm(PasswordChangeForm):
    def clean_new_password1(self):
        password1 = self.cleaned_data.get('new_password1')
        if len(password1) < 6:
            raise forms.ValidationError(_('Insert minimum six characters'))
        return password1


class CustomSetPasswordForm(SetPasswordForm):
    def clean_new_password1(self):
        password1 = self.cleaned_data.get('new_password1')
        if len(password1) < 6:
            raise forms.ValidationError(_('Insert minimum six characters'))
        return password1


class UserChangeForm(AuthUserChangeForm):
    class Meta(AuthUserChangeForm.Meta):
        model = User


class UserCreationForm(AuthUserCreationForm):
    class Meta(AuthUserCreationForm.Meta):
        model = User

    def clean_username(self):
        # Since User.username is unique, this check is redundant,
        # but it sets a nicer error message than the ORM. See #13147.
        username = self.cleaned_data["username"]
        try:
            self._meta.model._default_manager.get(username=username)
        except self._meta.model.DoesNotExist:
            return username
        raise forms.ValidationError(
            self.error_messages['duplicate_username'],
            code='duplicate_username',
        )
