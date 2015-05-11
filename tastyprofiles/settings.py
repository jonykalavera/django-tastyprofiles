# -*- coding: utf-8 -*-
from django.conf import settings

UIDB36_REGEX = '(?P<uidb36>[0-9A-Za-z]{1,13})'
TOKEN_REGEX = '(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})'

TASTYPROFILES_PUBLIC_SIGN_UP = getattr(
    settings, 'TASTYPROFILES_PUBLIC_SIGN_UP', True)
TASTYPROFILE_API_THROTTLE = getattr(
    settings, 'TASTYPROFILE_API_THROTTLE', 150)
TASTYPROFILE_API_TIMEFRAME = getattr(
    settings, 'TASTYPROFILE_API_TIMEFRAME', 3600)
TASTYPROFILE_API_EXPIRATION = getattr(
    settings, 'TASTYPROFILE_API_EXPIRATION', 604800)
