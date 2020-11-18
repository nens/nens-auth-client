# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
"""nens_auth_client URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from .apps import NensAuthClientConfig
from django.conf import settings
from django.contrib import admin
from nens_auth_client import views


try:
    from django.urls import re_path
except ImportError:  # Django 1.11 compatibility
    from django.conf.urls import url as re_path

app_name = NensAuthClientConfig.name

urlpatterns = [
    re_path("^authorize/$", views.authorize, name="authorize"),
    re_path("^login/$", views.login, name="login"),
    re_path("^logout/$", views.logout, name="logout"),
    re_path(
        r"^invitations/(?P<invite>\w+)/accept/",
        views.accept_invite,
        name="accept_invite",
    ),
    re_path(
        r"^invitations/(?P<invite>\w+)/reject/",
        views.reject_invite,
        name="reject_invite",
    ),
    re_path(
        r"^invitations/(?P<invite>\w+)/revoke/",
        views.revoke_invite,
        name="revoke_invite",
    ),
]

if settings.NENS_AUTH_STANDALONE:
    urlpatterns += [re_path("^admin/", admin.site.urls)]
