import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

SECRET_KEY = "django_pgcrypto_tests__this_is_not_very_secret"

INSTALLED_APPS = [
    "testapp",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
]

# ROOT_URLCONF = "urls"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("PGCRYPTO_TEST_DEFAULT_DATABASE", "postgres"),
        "USER": os.environ.get("PGCRYPTO_TEST_USER", "postgres"),
        "PASSWORD": os.environ.get("PGCRYPTO_TEST_PASSWORD", ""),
        "HOST": os.environ.get("PGCRYPTO_TEST_HOST", "localhost"),
        "PORT": os.environ.get("PGCRYPTO_TEST_PORT", 5432),
        "TEST": {"NAME": os.environ.get("PGCRYPTO_TEST_DATABASE", "django_pgcrypto")},
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True
