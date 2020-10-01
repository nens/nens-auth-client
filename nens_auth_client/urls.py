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
from django.conf import settings
from django.contrib import admin
from nens_auth_client import views


try:
    from django.urls import re_path
except ImportError:  # Django 1.11 compatibility
    from django.urls import url as re_path



urlpatterns = [
    re_path("^authorize/$", views.authorize, name="authorize"),
    re_path("^login/$", views.login, name="login"),
    re_path("^logout/$", views.logout, name="logout"),
]

if settings.NENS_AUTH_STANDALONE:
    urlpatterns += [re_path("^admin/", admin.site.urls)]
