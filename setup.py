import os
import re

from setuptools import find_packages, setup


def get_long_description():
    with open("README.md", "r") as readme:
        return readme.read()


def get_version():
    with open(os.path.join("pgcrypto", "base.py"), "r") as src:
        return re.match(r'.*__version__ = "(.*?)"', src.read(), re.S).group(1)


setup(
    name="django-pgcrypto",
    version=get_version(),
    description="Python and Django utilities for encrypted fields using pgcrypto.",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Dan Watson",
    author_email="dcwatson@gmail.com",
    url="https://github.com/dcwatson/django-pgcrypto",
    license="BSD",
    packages=find_packages(exclude=["testapp"]),
    install_requires=["cryptography"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Database",
    ],
)
