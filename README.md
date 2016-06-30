Django Tastyprofiles
====================

RESTful auth resource.

## Install

```bash
pip install -e git+ssh://git@git.interalia.net:22223/osc/django-tastyprofiles.git#egg=django-tastyprofiles
```

Define your custom user model as described in the docs.

https://docs.djangoproject.com/en/1.8/topics/auth/customizing/#substituting-a-custom-user-model

Define the custom user model resource like this to get all the custom endpoints.

api.py

```python
# -*- coding: utf-8 -*-
from tastyprofiles.api import user_resource_factory

BaseUserResource = user_resource_factory()


class UserResource(BaseUserResource):
    class Meta(BaseUserResource.Meta):
        pass
```
Forked from: https://git.interalia.net/osc/django-tastyprofile

by @jonykalavera
