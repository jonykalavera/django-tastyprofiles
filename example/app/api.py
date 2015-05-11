# -*- coding: utf-8 -*-
from tastyprofiles.api import user_resource_factory

BaseUserResource = user_resource_factory()


class UserResource(BaseUserResource):
    class Meta(BaseUserResource.Meta):
        pass
