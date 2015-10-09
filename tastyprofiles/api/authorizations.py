# coding: utf-8

from django.utils.translation import ugettext as _

from tastypie.authorization import Authorization
from tastypie.exceptions import Unauthorized

from ..settings import TASTYPROFILES_PUBLIC_SIGN_UP


class UserAuthorization(Authorization):

    def read_list(self, object_list, bundle):
        return []

    def create_detail(self, object_list, bundle):
        return TASTYPROFILES_PUBLIC_SIGN_UP

    def create_list(self, object_list, bundle):
        return Unauthorized(_("Sorry, no bulk creation."))

    def update_list(self, object_list, bundle):
        allowed = []

        # Since they may not all be saved, iterate over them.
        for obj in object_list:
            if obj == bundle.request.user:
                allowed.append(obj)

        return allowed

    def update_detail(self, object_list, bundle):
        return bundle.obj == bundle.request.user
