from setuptools import setup

version = "1.3"

long_description = "\n\n".join(
    [
        open("README.rst").read(),
        open("CHANGES.rst").read(),
    ]
)

install_requires = [
    "Django",
    "authlib>=1.2",
    "django-appconf",
    "requests",
]

tests_require = [
    "djangorestframework",
    "flake8",
    "pytest",
    "pytest-cov",
    "pytest-django",
    "pytest-mock",
    "requests-mock",
]

setup(
    name="nens-auth-client",
    python_requires=">=3.6",
    version=version,
    description="An OAuth2 client library for AWS Cognito",
    long_description=long_description,
    # Get strings from http://www.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        "Programming Language :: Python",
        "Framework :: Django",
    ],
    keywords=[],
    author="Casper van der Wel",
    author_email="casper.vanderwel@nelen-schuurmans.nl",
    url="https://github.com/nens/nens-auth-client",
    license="BSD 3-Clause",
    packages=["nens_auth_client"],
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={"test": tests_require},
    entry_points={"console_scripts": []},
)
