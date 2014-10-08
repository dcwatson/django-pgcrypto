#! /usr/bin/env python
"""From http://stackoverflow.com/a/12260597/400691"""
import sys

from colour_runner.django_runner import ColourRunnerMixin
from django.conf import settings


settings.configure(
    MIDDLEWARE_CLASSES = (),
)

import django
if django.VERSION >= (1, 7):
    django.setup()

from django.test.runner import DiscoverRunner


class TestRunner(ColourRunnerMixin, DiscoverRunner):
    pass


test_runner = TestRunner(verbosity=1)
failures = test_runner.run_tests(['pgcrypto'])
if failures:
    sys.exit(1)
