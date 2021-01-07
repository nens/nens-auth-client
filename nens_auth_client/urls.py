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


def override_admin_auth(admin_path="admin"):
    """Return login/logout url paths to enable cognito-based authentication.
    
    This should be included in the urlpatterns of the root site before
    the admin urls are included.

    The login and logout paths are overriden. An admin/local-login/ path is
    added for backdoor access with local accounts.
    """
    return [
        re_path("^{}/login/".format(admin_path), views.login, name="admin-login-override"),
        re_path("^{}/logout/".format(admin_path), views.logout, name="admin-logout-override"),
        re_path("^{}/local-login/".format(admin_path), admin.site.login, name="admin-local-login")
    ]


def override_rest_framework_auth(drf_path="api-auth"):
    """Return login/logout url paths to enable cognito-based authentication.
    
    This should be included in the urlpatterns of the root site before
    the rest_framework urls are included.

    The login and logout paths are overriden.
    """
    return [
        re_path("^{}/login/".format(drf_path), views.login, name="drf-login-override"),
        re_path("^{}/logout/".format(drf_path), views.logout, name="drf-logout-override"),
    ]


app_name = NensAuthClientConfig.name

urlpatterns = [
    re_path("^authorize/$", views.authorize, name="authorize"),
    re_path("^login/$", views.login, name="login"),
    re_path("^logout/$", views.logout, name="logout"),
    re_path(
        r"^invitations/(?P<slug>\w+)/accept/",
        views.accept_invitation,
        name="accept_invitation",
    ),
]

if settings.NENS_AUTH_STANDALONE:
    urlpatterns += [
        *override_admin_auth(),
        re_path("^admin/", admin.site.urls)
    ]
