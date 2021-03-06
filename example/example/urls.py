"""example URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf import settings
from django.conf.urls import include, url
from django.conf.urls.static import static
from django.contrib import admin

from tastypie.api import Api

from app.api import UserResource

v1_api = Api(api_name='v1')
v1_api.register(UserResource())


urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
    url(r'^api/', include(v1_api.urls)),
]

if settings.DEBUG:
    urlpatterns = [
        url(
            r'^api/v1/doc/',
            include('tastypie_swagger.urls', namespace='tastypie_swagger'),
            kwargs={
                "tastypie_api_module": "example.urls.v1_api",
                "namespace": "tastypie_swagger"
            }
        )
    ] + urlpatterns + static(
        settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) + static(
        settings.STATIC_URL, document_root=settings.STATIC_ROOT)
