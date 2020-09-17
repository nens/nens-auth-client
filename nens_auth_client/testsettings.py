# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# Base Django settings, suitable for production.
# Imported (and partly overridden) by developmentsettings.py which also
# imports localsettings.py (which isn't stored in svn).  Buildout takes care
# of using the correct one.
# So: "DEBUG = TRUE" goes into developmentsettings.py and per-developer
# database ports go into localsettings.py.  May your hear turn purple if you
# ever put personal settings into this file or into developmentsettings.py!

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
# In older projects, this setting is called BUILDOUT_DIR
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEBUG = True

# TODO: Switch this to the real production database.
# ^^^ 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
# In case of geodatabase, prepend with: django.contrib.gis.db.backends.(postgis)
DATABASES = {
    'default': {
        'NAME': BASE_DIR + '/db.sqlite3',
        'ENGINE': 'django.db.backends.sqlite3',
        }
    }

# Almost always set to 1.  Django allows multiple sites in one database.
SITE_ID = 1

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name although not all
# choices may be available on all operating systems.  If running in a Windows
# environment this must be set to the same as your system time zone.
TIME_ZONE = 'Europe/Amsterdam'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'nl-NL'
# For at-runtime language switching.  Note: they're shown in reverse order in
# the interface!
LANGUAGES = (
#    ('en', 'English'),
    ('nl', 'Nederlands'),
)
# If you set this to False, Django will make some optimizations so as not to
# load the internationalization machinery.
USE_I18N = True

USE_L10N = True

USE_TZ = True

# Absolute path to the directory that holds user-uploaded media.
MEDIA_ROOT = os.path.join(BASE_DIR, 'var', 'media')
# Absolute path to the directory where
# "python manage.py collectstatic" places all collected static files from all
# applications' /media directory.
STATIC_ROOT = os.path.join(BASE_DIR, 'var', 'static')

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash if there is a path component (optional in other cases).
MEDIA_URL = '/media/'
# URL for the per-application /media static files collected by
# django-staticfiles.
STATIC_URL = '/static_media/'

# Make this unique, and don't share it with anybody.
SECRET_KEY = "ux0=hfx-ax^%@0v9u==app#x&7gszmy&b!bn1u&fac+8l0%obm"

ROOT_URLCONF = 'nens_auth_client.urls'

TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'debug': DEBUG,
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

MIDDLEWARE = (
    # Below is the default list, don't modify it.
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    )

INSTALLED_APPS = (
    'nens_auth_client',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.messages',
    'django.contrib.sessions',
    'django.contrib.staticfiles',
)

# Add your production name here
ALLOWED_HOSTS = ['localhost']

NENS_AUTH_STANDALONE = True  # for testing
NENS_AUTH_CLIENT_ID = "1f1rf3n93dnsvb6jinske1ccrl"
NENS_AUTH_CLIENT_SECRET = "1eqdu9bffroptll5bt3lejetkusqaln0ve8ad6l8clg1igoo0728"
NENS_AUTH_REDIRECT_URI = "http://localhost:8000/authorize"
