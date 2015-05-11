# coding: utf-8
from django.conf import settings

from django.contrib.auth.models import AbstractUser, UserManager
from django.db import models
from django.utils.translation import ugettext_lazy as _


class User(AbstractUser):
    """
    Custo user model.
    """
    about_me = models.TextField(null=True, blank=True)

    objects = UserManager()

    REQUIRED_FIELDS = ['email']

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
