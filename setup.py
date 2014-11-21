import os
import re

from setuptools import find_packages, setup


def get_version():
    dirname = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(dirname, 'pgcrypto', 'base.py')) as handler:
        content = handler.read()

    version_info = re.findall(r'__version_info__ = \(([^)]+)\)', content)[0]
    return '.'.join(item.strip().strip('"').strip("'")
                    for item in version_info.split(','))


setup(
    name='django-pgcrypto',
    version=get_version(),
    description='Python and Django utilities for encrypted fields using '
                'pgcrypto.',
    author='Dan Watson',
    author_email='dcwatson@gmail.com',
    url='https://github.com/dcwatson/django-pgcrypto',
    license='BSD',
    packages=find_packages(),
    install_requires=[
        'Django>=1.5',
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
