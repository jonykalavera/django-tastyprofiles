from django.contrib import admin

from tastyprofiles.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth import get_user_model

User = get_user_model()


class UserAdmin(BaseUserAdmin):
    list_display = BaseUserAdmin.list_display + ('about_me',)

admin.site.register(User, UserAdmin)
