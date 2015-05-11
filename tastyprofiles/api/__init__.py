# -*- coding: utf-8 -*-
from django.contrib.auth import get_user_model

from .resources import UserResourceBase


def user_resource_factory(user_model=None):
    if user_model is None:
        user_model = get_user_model()

    class UserResource(UserResourceBase):
        class Meta(UserResourceBase.Meta):
            queryset = user_model.objects.filter(is_active=True)
    return UserResource
