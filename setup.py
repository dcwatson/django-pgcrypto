from setuptools import setup, find_packages
import os
import re

def get_version():
    with open(os.path.join(os.path.dirname(__file__), 'pgcrypto', 'base.py')) as fp:
        return re.match(r".*__version__ = '(.*?)'", fp.read(), re.S).group(1)

setup(
    name='django-pgcrypto',
    version=get_version(),
    description='Python and Django utilities for encrypted fields using pgcrypto.',
    author='Dan Watson',
    author_email='dcwatson@gmail.com',
    url='https://github.com/dcwatson/django-pgcrypto',
    license='BSD',
    packages=find_packages(),
    install_requires=[
        'pycrypto>=2.6',
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Database',
    ]
)
