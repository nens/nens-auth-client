from setuptools import setup

version = '0.8'

long_description = '\n\n'.join([
    open('README.rst').read(),
    open('CHANGES.rst').read(),
])

install_requires = [
    'Django',
    'django-appconf',
    'authlib[client]',
    'requests',
]

tests_require = [
    'pytest',
    'pytest-cov',
    'pytest-django',
    'pytest-mock',
    'requests-mock',
    'flake8'
]

setup(name='nens-auth-client',
      version=version,
      description="An OAuth2 client library for AWS Cognito",
      long_description=long_description,
      # Get strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      classifiers=['Programming Language :: Python',
                   'Framework :: Django',
                   ],
      keywords=[],
      author='Casper van der Wel',
      author_email='casper.vanderwel@nelen-schuurmans.nl',
      url="https://github.com/nens/nens-auth-client",
      license="BSD 3-Clause",
      packages=['nens_auth_client'],
      include_package_data=True,
      zip_safe=False,
      install_requires=install_requires,
      tests_require=tests_require,
      extras_require={'test': tests_require},
      entry_points={
          'console_scripts': [
          ]},
      )
