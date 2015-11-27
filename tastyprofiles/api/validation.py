# -*- coding: utf-8 -*-

from django.utils.translation import ugettext as _

from tastypie.validation import CleanedDataFormValidation


class UserValidation(CleanedDataFormValidation):
    def __init__(self, **kwargs):
        if 'update_form_class' not in kwargs:
            raise ImproperlyConfigured(
                _("You must provide a 'update_form_class'."))
        self._update_form_class = kwargs.pop('update_form_class')
        super(UserValidation, self).__init__(**kwargs)
        self._default_form_class = self.form_class

    def is_valid(self, bundle, request=None):
        if request and request.method in ['PATCH', 'PUT']:
            self.form_class = self._update_form_class
        else:
            self.form_class = self._default_form_class
        return super(UserValidation, self).is_valid(bundle, request)
