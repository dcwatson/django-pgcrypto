from setuptools import setup, find_packages
from pgcrypto.base import __version__

setup(
    name='django-pgcrypto',
    version=__version__,
    description='Python and Django utilities for encrypted fields using pgcrypto.',
    author='Dan Watson',
    author_email='dcwatson@gmail.com',
    url='https://github.com/dcwatson/django-pgcrypto',
    license='BSD',
    packages=find_packages(),
    install_requires=[
        'pycrypto>=2.6',
        'Django>=1.6',
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
