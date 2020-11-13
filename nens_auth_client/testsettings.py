# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# Django settings only suitable for standalone test environments.

import os


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEBUG = True

DATABASES = {
    "default": {
        "NAME": BASE_DIR + "/db.sqlite3",
        "ENGINE": "django.db.backends.sqlite3",
    }
}

# Almost always set to 1.  Django allows multiple sites in one database.
SITE_ID = 1

# Required for django.contrib.staticfiles
STATIC_URL = "/static_media/"

# Make this unique, and don't share it with anybody.
SECRET_KEY = "ux0=hfx-ax^%@0v9u==app#x&7gszmy&b!bn1u&fac+8l0%obm"

ROOT_URLCONF = "nens_auth_client.urls"

# Required for django.contrib.admin
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "debug": DEBUG,
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "require_debug_false": {
            "()": "django.utils.log.RequireDebugFalse",
        },
        "require_debug_true": {
            "()": "django.utils.log.RequireDebugTrue",
        },
    },
    "formatters": {
        "django.server": {
            "()": "django.utils.log.ServerFormatter",
            "format": "[{server_time}] {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "level": "INFO",
            "filters": ["require_debug_true"],
            "class": "logging.StreamHandler",
        },
        "django.server": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "django.server",
        },
        "urllib3": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "django.server",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
        },
        "django.server": {
            "handlers": ["django.server"],
            "level": "INFO",
            "propagate": False,
        },
        "urllib3": {
            "handlers": ["urllib3"],
            "level": "DEBUG",
        },
    }
}

MIDDLEWARE = (
    # Below is the default list, don't modify it.
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "nens_auth_client.middleware.AccessTokenMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
)

INSTALLED_APPS = (
    "nens_auth_client",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.messages",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
)

# Add your production name here
ALLOWED_HOSTS = ["localhost"]

AUTHENTICATION_BACKENDS = [
    "nens_auth_client.backends.RemoteUserBackend",
    "nens_auth_client.backends.SSOMigrationBackend",
    "django.contrib.auth.backends.ModelBackend"
]

NENS_AUTH_STANDALONE = True  # for testing
NENS_AUTH_URL_NAMESPACE = ""  # nens_auth_client urls.py is the root url conf
NENS_AUTH_CLIENT_ID = "1f1rf3n93dnsvb6jinske1ccrl"
NENS_AUTH_CLIENT_SECRET = "1eqdu9bffroptll5bt3lejetkusqaln0ve8ad6l8clg1igoo0728"
NENS_AUTH_ISSUER = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_9AyLE4ffV"
NENS_AUTH_DEFAULT_LOGOUT_URL = "/admin/"
NENS_AUTH_DEFAULT_SUCCESS_URL = "/admin/"
NENS_AUTH_RESOURCE_SERVER_ID = "http://localhost:8000/admin/"  # trailing slash
