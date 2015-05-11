# coding: utf-8
from django.contrib import admin
from django.utils.translation import ugettext, ugettext_lazy as _

from django.contrib.auth.admin import UserAdmin as AuthUserAdmin

from .forms import UserChangeForm, UserCreationForm


class UserAdmin(AuthUserAdmin):
    list_display = (
        'username', 'email', 'is_staff', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    fieldsets = (
        (None, {'fields': (
            'username', 'email', 'password',)}),
        (_('Personal info'), {'fields': (
            'first_name', 'last_name',
            )}),
        (_('Permissions'), {'fields': (
            'is_active', 'is_staff', 'is_superuser', 'groups',
            'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    ordering = ('date_joined',)
    form = UserChangeForm
    add_form = UserCreationForm
    list_filter = ('is_staff',)
