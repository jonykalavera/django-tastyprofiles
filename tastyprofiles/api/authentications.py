# -*- coding: utf-8 -*-
from tastypie.authentication import SessionAuthentication


class UserAuthentication(SessionAuthentication):
    """ No auth on post / for user creation """

    def is_authenticated(self, request, **kwargs):
        """ If POST, don't check auth, otherwise fall back to parent """

        if request.method == "POST":
            return True
        else:
            return super(UserAuthentication, self).is_authenticated(
                request, **kwargs)
