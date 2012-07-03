from distutils.core import setup
import pgcrypto

setup(
    name='django-pgcrypto',
    version=pgcrypto.__version__,
    description='Python and Django utilities for encrypted fields using pgcrypto.',
    author='Dan Watson',
    author_email='dcwatson@gmail.com',
    url='https://github.com/dcwatson/django-pgcrypto',
    license='BSD',
    py_modules=['pgcrypto'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Topic :: Database',
    ]
)
