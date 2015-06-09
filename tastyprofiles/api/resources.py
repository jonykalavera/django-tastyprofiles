# coding: utf-8
try:
    import json
except ImportError:
    import simplejson as json

from django.conf import settings
from django.conf.urls import url
from django.contrib.auth import (
    login as auth_login, logout, update_session_auth_hash, get_user_model)
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.tokens import default_token_generator
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, Http404
from django.utils.http import urlsafe_base64_decode
from django.utils.translation import ugettext as _

from tastypie.cache import SimpleCache, NoCache
from tastypie.exceptions import BadRequest
from tastypie.resources import ModelResource
from tastypie.throttle import CacheThrottle
from tastypie.serializers import Serializer

from ..forms import UserForm, UpdateUserForm, \
    CustomPasswordResetForm, CustomPasswordChangeForm, CustomSetPasswordForm
from ..settings import UIDB36_REGEX, TOKEN_REGEX, TASTYPROFILE_API_THROTTLE, \
    TASTYPROFILE_API_TIMEFRAME, TASTYPROFILE_API_EXPIRATION


from .authentications import UserAuthentication
from .authorizations import UserAuthorization
from .validation import UserValidation

User = get_user_model()


class UserResourceBase(ModelResource):
    class Meta:
        queryset = User.objects.filter(is_active=True)
        resource_name = 'user'
        detail_uri_name = 'username'
        authentication = UserAuthentication()
        authorization = UserAuthorization()
        throttle = CacheThrottle(
            throttle_at=TASTYPROFILE_API_THROTTLE,
            timeframe=TASTYPROFILE_API_TIMEFRAME,
            expiration=TASTYPROFILE_API_EXPIRATION)
        excludes = ['password']
        post_excludes = ['id']

        include_resource_uri = False
        allowed_methods = ['get', 'post', 'patch', 'put']
        validation = UserValidation(
            form_class=UserForm, update_form_class=UpdateUserForm)
        serializer = Serializer(formats=['json', 'jsonp'])
        # cache = SimpleCache(timeout=60*150)
        # always_return_data = True
        # Swagger UI Documentation.
        extra_actions = [
            {
                "name": "login",
                "http_method": "POST",
                "resource_type": "list",
                "description": "Sign in usin email, password credentials.",
                "fields": {
                    "credentials": {
                        "param_type": 'body',
                        "type": "dict",
                        "required": True,
                        "description": "User credentials to atempt sign-in. "
                        "Ex. {\"email\":.., \"password\":...}."
                    }
                }
            },
            {
                "name": "logout",
                "http_method": "POST",
                "resource_type": "list",
                "description": "Logout user.",
                "fields": {}
            },
            {
                "name": "password-reset",
                "http_method": "POST",
                "resource_type": "list",
                "description": "Password recovery service api.",
                "fields": {
                    "email": {
                        "param_type": 'body',
                        "type": "dict",
                        "required": True,
                        "description":
                            "Json dict with the email to recive the token."
                    }
                }
            },
            {
                "name": "password-reset/{uidb36}-{token}",
                "nickname": "password-reset-confirm",
                "http_method": "POST",
                "resource_type": "list",
                "description": "Password recovery confirmation api.",
                "fields": {
                    "uidb36": {
                        "param_type": 'path',
                        "type": "text",
                        "required": True,
                        "description":
                            "Uid encoded as base36."
                    },
                    "token": {
                        "param_type": 'path',
                        "type": "text",
                        "required": True,
                        "description":
                            "Recovery token."
                    },
                    "new_password": {
                        "param_type": 'body',
                        "type": "dict",
                        "required": True,
                        "description":
                            "Json dict with new_password1 "
                            "and new_password2 confirmation."
                    }
                }
            },
            {
                "name": "password-change",
                "http_method": "POST",
                # "resource_type": "list",
                "description": "Password change self-service api.",
                "fields": {
                    "new_password": {
                        "param_type": 'body',
                        "type": "dict",
                        "required": True,
                        "description":
                            "Json dict with old_password, new_password1 "
                            "and new_password2 confirmation."
                    }
                }
            },
        ]

    def obj_create(self, bundle, **kwargs):
        """
        User creation override.
        """
        # Eliminar elementos que no deseamos que pueda guardar el usuario
        for key in bundle.data.keys():
            if key in getattr(self._meta, 'post_excludes', []):
                bundle.data.pop(key)

        if not bundle.data.get('facebook_name'):
            last_name = bundle.data.get('last_name', '')
            first_name = bundle.data.get('first_name', '')
            bundle.data['facebook_name'] = first_name + ' ' + last_name
        if not bundle.data.get('username'):
            bundle.data['username'] = bundle.data.get('email', '')

        bundle = super(UserResourceBase, self).obj_create(bundle, **kwargs)
        bundle.obj.set_password(bundle.data.get('password'))
        bundle.obj.save()

        return bundle

    def prepend_urls(self, *args, **kwargs):
        """
        Overriden to add custom end-points.
        """
        return [
            url(r"^(?P<resource_name>%s)/me/$" %
                self._meta.resource_name, self.wrap_view('dispatch_me'),
                name="api_dispatch_me"),
            url(r"^(?P<resource_name>%s)/login/$" %
                self._meta.resource_name, self.wrap_view('dispatch_login'),
                name="api_dispatch_login"),
            url(r"^(?P<resource_name>%s)/logout/$" %
                self._meta.resource_name, self.wrap_view('dispatch_logout'),
                name="api_dispatch_logout"),
            url(r"^(?P<resource_name>%s)/password-reset/$" %
                self._meta.resource_name,
                self.wrap_view('dispatch_password_reset'),
                name="api_dispatch_password_reset"),
            url(r"^(?P<resource_name>%s)/password-reset/%s-%s/$" %
                (self._meta.resource_name, UIDB36_REGEX, TOKEN_REGEX),
                self.wrap_view('dispatch_password_reset_confirm'),
                name="api_dispatch_password_reset_confirm"),
            url(r"^(?P<resource_name>%s)/(?P<username>[\w\d_.-]+)/$" %
                self._meta.resource_name, self.wrap_view('dispatch_detail'),
                name="api_dispatch_detail"),
            url(r"^(?P<resource_name>%s)/(?P<username>[\w\d_.-]+)/"
                "password-change/$" % self._meta.resource_name,
                self.wrap_view('dispatch_password_change'),
                name="api_dispatch_password_change"),
        ]

    def dispatch_me(self, request, **kwargs):
        """
        Redirect to loged_in user end-point.
        """
        if request.user.is_authenticated():
            url = reverse('api_dispatch_detail', args=(
                'v1', 'user', request.user.username,), kwargs={})
            query_string = request.META.get('QUERY_STRING')

            if query_string:
                url += "?"+query_string
            return HttpResponseRedirect(url)
        response = {
            'loged_in': request.user.is_authenticated(),
            'user': request.user,
        }
        return self.create_response(request, response)

    def dispatch_logout(self, request, **kwargs):
        """
        Logout end-point.
        """
        self.method_check(request, allowed=['post'])
        # self.is_authenticated(request)
        self.throttle_check(request)
        logout(request)
        response = {
            'success': True
        }
        return self.create_response(request, response)

    def dispatch_login(self, request, **kwargs):
        """
        Login service end-point.
        """
        self.method_check(request, allowed=['post'])
        # self.is_authenticated(request)
        # self.throttle_check(request)
        try:
            data = json.loads(request.body)
        except:
            raise BadRequest('Bad data :S')

        username = data.get('username', '')
        email = data.get('email', '')
        password = data.get('password', '')
        user = None
        logged_in = False

        if email and not username:
            try:
                user = User.objects.get(email=email)
                username = user.username
            except User.DoesNotExist:
                pass

        form = AuthenticationForm(data={
            'username': username, 'password': password
        })
        if form.is_valid():
            user = form.get_user()
            if user:
                auth_login(request, user)
                logged_in = True

        response = {
            'success': logged_in,
        }
        if logged_in and user:
            bundle = self.build_bundle(obj=user, request=request)
            response['user'] = self.full_dehydrate(bundle)
        # self.log_throttled_access(request)
        return self.create_response(request, response)

    def dispatch_password_change(self, request, **kwargs):
        """
        Password change self-service end-point.
        """
        self.method_check(request, allowed=['post'])
        self.is_authenticated(request)
        self.throttle_check(request)

        username = kwargs.get('username')

        response = {
            'success': False,
        }
        status_code = 400
        if request.user.is_authenticated() and \
                username == request.user.username:
            try:
                data = json.loads(request.body)
            except:
                raise BadRequest('Bad data :S')
            form = CustomPasswordChangeForm(user=request.user, data=data)
            if form.is_valid():
                form.save()
                # Updating the password logs out all other sessions for the
                # user except the current one if
                # django.contrib.auth.middleware.SessionAuthenticationMiddleware
                # is enabled.
                update_session_auth_hash(request, form.user)
                response['success'] = True
                status_code = 200
            else:
                response['errors'] = form._errors
        else:
            response['errors'] = {
                '__all__': _('Password change unsuccessful.')
            }

        bundle = self.build_bundle(data=response, request=request)
        return self.create_response(request, bundle, status=status_code)

    def dispatch_password_reset(self, request, **kwargs):
        """
        Request password reset token service.
        """
        self.method_check(request, allowed=['post'])

        try:
            data = json.loads(request.body)
        except:
            raise BadRequest('Bad data :S')

        email = data.get('email', '')
        status_code = 400
        if self._meta.cache.get(email):
            response = {
                'success': 'Correo ya enviado',
            }
            status_code = 200
            bundle = self.build_bundle(data=response, request=request)
            return self.create_response(request, bundle, status=status_code)

        self._meta.cache.set(email, True)
        form = CustomPasswordResetForm(data)
        response = {
            'success': 'False',
        }
        if form.is_valid():
            opts = {
                'use_https': request.is_secure(),
                'token_generator': default_token_generator,
                # 'from_email': settings.EMAIL_FROM,
                'email_template_name':
                    'tastyprofiles/email/password_reset_email.txt',
                'subject_template_name':
                    'tastyprofiles/email/password_reset_subject.txt',
                'request': request,
                'html_email_template_name':
                    'tastyprofiles/email/password_reset_email.html',
            }
            form.save(**opts)
            response['success'] = True
            status_code = 200
        else:
            response['errors'] = form._errors
        bundle = self.build_bundle(data=response, request=request)
        return self.create_response(request, bundle, status=status_code)

    def dispatch_password_reset_confirm(self, request, **kwargs):
        """
        Confirm password reset service.
        """

        self.method_check(request, allowed=['post'])
        self.throttle_check(request)

        # assert False, dir(request)
        uidb64 = kwargs.get('uidb36')
        token = kwargs.get('token')
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = User._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        response = {
            'success': False,
        }
        status_code = 400
        if user is not None and \
                default_token_generator.check_token(user, token):
            try:
                data = json.loads(request.body)
            except:
                raise BadRequest('Bad data :S')
            form = CustomSetPasswordForm(user, data)
            if form.is_valid():
                form.save()
                response['success'] = True
                status_code = 200
            else:
                response['errors'] = form._errors
        else:
            response['errors'] = {
                '__all__': _('Password reset unsuccessful')
            }

        bundle = self.build_bundle(data=response, request=request)
        return self.create_response(request, bundle, status=status_code)
