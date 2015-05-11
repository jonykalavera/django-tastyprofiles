# coding: utf-8
"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""
import datetime
try:
    import json
except ImportError:
    import simplejson as json
import os
import re
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.urlresolvers import reverse
from django.test import TestCase, RequestFactory, Client


from tastyprofiles.api import user_resource_factory
# from mailer.models import Message

from .settings import UIDB36_REGEX, TOKEN_REGEX, TASTYPROFILE_API_THROTTLE, \
    TASTYPROFILE_API_TIMEFRAME

User = get_user_model()
UserResource = user_resource_factory()


class ProfileTestCase(TestCase):

    def setUp(self):
        self.client = Client()
        # Every test needs access to the request factory.
        self.factory = RequestFactory()
        self.admin = User.objects.create_user(
            username='admin', email='admin@example.com', password='123456')
        self.user = User.objects.create_user(
            username='tester', email='tester@example.com', password='654321')

        os.environ['RECAPTCHA_TESTING'] = 'True'

    def _login_with_api(self, email, password):
        """
        Perform login attempt using the login service.
        """
        data = {
            'email': email,
            'password': password,
        }
        body = json.dumps(data)
        response = self.client.post(
            reverse("api_dispatch_login", kwargs={
                "resource_name": "user",
                "api_name": "v1",
            }), data=body, follow=True,
            content_type='application/json')
        return response

    def test_login(self):
        """
        Tests that login service works like a charm.
        """
        # self.client.logout()
        response = self._login_with_api('tester@example.com', '654321')

        self.assertEqual(response.status_code, 200)
        # print "== response:", response.content
        response_data = json.loads(response.content)

        self.assertEqual(response_data.get('success'), True)

    def test_logout(self):
        """
        Tests that logout service works like a charm.
        """
        self.client.logout()
        loged_in = self.client.login(username='admin', password='123456')
        self.assertEqual(loged_in, True)
        response = self.client.post(
            reverse("api_dispatch_logout", kwargs={
                "resource_name": "user",
                "api_name": "v1",
            }), follow=True,
            content_type='application/json')

        self.assertEqual(response.status_code, 200)
        # print response.content
        response_data = json.loads(response.content)
        self.assertEqual(response_data.get('success'), True)

    def test_user_api_detail(self):
        """
        Test user api detail response.
        """
        loged_in = self.client.login(username='tester', password='654321')
        self.assertEqual(loged_in, True)
        response = self.client.get(
            reverse("api_dispatch_me", kwargs={
                "resource_name": "user",
                "api_name": "v1",
            }), {'format': 'json'}, follow=True)

        self.assertEqual(response.status_code, 200)
        admin_data = json.loads(response.content)

        self.assertEqual(admin_data.get('username'), 'tester')

        for i in range(TASTYPROFILE_API_THROTTLE):
            response = self.client.get(
                reverse("api_dispatch_me", kwargs={
                    "resource_name": "user",
                    "api_name": "v1",
                }), {'format': 'json'}, follow=True)

        self.assertEqual(response.status_code, 429)

        time.sleep(TASTYPROFILE_API_TIMEFRAME + 1)

        response = self.client.get(
            reverse("api_dispatch_me", kwargs={
                "resource_name": "user",
                "api_name": "v1",
            }), {'format': 'json'}, follow=True)
        self.assertEqual(response.status_code, 200)
        admin_data = json.loads(response.content)
        self.assertEqual(admin_data.get('username'), 'tester')

    def _register_with_api(self, data):
        """
        Request user registration using REST Api.
        """
        self.client.logout()
        json_data = json.dumps(data)
        os.environ['RECAPTCHA_TESTING'] = 'True'
        response = self.client.post(
            reverse("api_dispatch_list", kwargs={
                "resource_name": "user",
                "api_name": "v1",
            }), data=json_data,
            content_type='application/json')
        return response

    def test_register(self):
        """
        Test successful user registration and login with that user.
        """
        mail.outbox = []
        response = self._register_with_api({
            'first_name': 'Testy',
            'last_name': 'Testerson',
            'email': 'testy@test.com',
            'password': 'roman.polansky',
            'repeat_password': 'roman.polansky',
            'g-recaptcha-response': 'PASSED',
        })

        print response.content

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.content, '')

        # Try to login with newly created user.
        response = self._login_with_api('testy@test.com', 'roman.polansky')
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertEqual(response_data.get('success'), True)

        response = self.client.get(
            reverse("api_dispatch_me", kwargs={
                "resource_name": "user",
                "api_name": "v1",
            }), {'format': 'json'}, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_register_errors(self):
        """
        Test errors for void input.
        """
        self.client.logout()
        response = self._register_with_api({})
        # print "== response:", response.content
        self.assertEqual(response.status_code, 400)
        error_data = json.loads(response.content)
        self.assertEqual(type(error_data.get('user')), dict)
        # assert False, set(error_data.get('user').keys())
        self.assertTrue(
            set([
                u'username', u'first_name', u'last_name',
                u'repeat_password', u'captcha',
                u'password', u'email',
            ]).issubset(set(error_data.get('user').keys()))
        )

    def test_user_update(self):
        """
        Test successful profile update.
        """
        loged_in = self.client.login(username='tester', password='654321')
        data = {
            'first_name': 'Changed',
            'email_alt': 'alternative@example.com',
            'state': 'JAL'
        }
        json_data = json.dumps(data)
        response = self.client.patch(
            reverse("api_dispatch_detail", kwargs={
                "resource_name": "user",
                "api_name": "v1",
                "username": "tester"
            }), data=json_data,
            content_type='application/json')

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.content, '')
        user = User.objects.get(username='tester')
        self.assertEqual(user.first_name, 'Changed')

    def test_password_reset(self):
        """
        Test the password reset service.
        """
        mail.outbox = []
        self.client.logout()
        json_data = json.dumps({
            'email': 'tester@example.com'
        })
        UserResource._meta.cache.set('tester@example.com', False)
        response = self.client.post(
            reverse("api_dispatch_password_reset", kwargs={
                "resource_name": "user",
                "api_name": "v1",
            }), data=json_data, content_type='application/json')
        data = json.loads(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data.get('success'))
        # Test that one message has been sent.
        self.assertEqual(len(mail.outbox), 1)
        password_reset_email = mail.outbox[0]

        # Verify that the subject of the first message is correct.
        self.assertEqual(
            password_reset_email.subject,
            u'Password reset on testserver')

        match = re.search(
            r'\?token=%s-%s' % (UIDB36_REGEX, TOKEN_REGEX),
            str(password_reset_email.message()))
        uidb36 = match.group('uidb36')
        token = match.group('token')
        json_data = json.dumps({
            'new_password1': '123456',
            'new_password2': '123456',
        })

        response = self.client.post(
            reverse("api_dispatch_password_reset_confirm", kwargs={
                "resource_name": "user",
                "api_name": "v1",
                "uidb36": uidb36,
                "token": token,
            }),
            data=json_data, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data.get('success'))

        loged_in = self.client.login(username='tester', password='123456')
        self.assertTrue(loged_in)

    def test_password_change(self):
        """
        Test the password change service.
        """
        # Test unauthenticated request
        self.client.logout()
        json_data = json.dumps({})
        response = self.client.post(
            '/api/v1/user/tester/password-change/', data=json_data,
            content_type='application/json')
        self.assertEqual(response.status_code, 400)

        loged_in = self.client.login(username='tester', password='654321')
        self.assertTrue(loged_in)
        # Bad data
        json_data = ""
        response = self.client.post(
            reverse("api_dispatch_password_change", kwargs={
                "resource_name": "user",
                "api_name": "v1",
                "username": "tester",
            }), data=json_data,
            content_type='application/json')
        self.assertEqual(response.status_code, 400)

        # Test missing parameters
        json_data = ""
        response = self.client.post(
            reverse("api_dispatch_password_change", kwargs={
                "resource_name": "user",
                "api_name": "v1",
                "username": "tester",
            }), data=json_data,
            content_type='application/json')
        self.assertEqual(response.status_code, 400)

        json_data = json.dumps({
            'old_password': '654321',
            'new_password1': '123456',
            'new_password2': '123456',
        })
        response = self.client.post(
            reverse("api_dispatch_password_change", kwargs={
                "resource_name": "user",
                "api_name": "v1",
                "username": "tester",
            }), data=json_data,
            content_type='application/json')
        data = json.loads(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data.get('success'))
