from Crypto.Cipher import AES, Blowfish
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.utils import IntegrityError
from django.test import TestCase

from pgcrypto import aes_pad_key, armor, dearmor, pad, unpad

from .models import Employee

import decimal
import json
import os
import unittest


class CryptoTests (unittest.TestCase):

    def setUp(self):
        # This is the expected Blowfish-encrypted value, according to the following pgcrypto call:
        #     select encrypt('sensitive information', 'pass', 'bf');
        self.encrypt_bf = b"x\364r\225\356WH\347\240\205\211a\223I{~\233\034\347\217/f\035\005"
        # The basic "encrypt" call assumes an all-NUL IV of the appropriate block size.
        self.iv_blowfish = b"\0" * Blowfish.block_size
        # This is the expected AES-encrypted value, according to the following pgcrypto call:
        #     select encrypt('sensitive information', 'pass', 'aes');
        self.encrypt_aes = b"\263r\011\033]Q1\220\340\247\317Y,\321q\224KmuHf>Z\011M\032\316\376&z\330\344"
        # The basic "encrypt" call assumes an all-NUL IV of the appropriate block size.
        self.iv_aes = b"\0" * AES.block_size
        # When encrypting a string whose length is a multiple of the block size, pgcrypto
        # tacks on an extra block of padding, so it can reliably unpad afterwards. This
        # data was generated from the following query (string length = 16):
        #     select encrypt('xxxxxxxxxxxxxxxx', 'secret', 'aes');
        self.encrypt_aes_padded = b"5M\304\316\240B$Z\351\021PD\317\213\213\234f\225L \342\004SIX\030\331S\376\371\220\\"

    def test_encrypt(self):
        c = Blowfish.new('pass', Blowfish.MODE_CBC, self.iv_blowfish)
        self.assertEqual(c.encrypt(pad(b'sensitive information', c.block_size)), self.encrypt_bf)

    def test_decrypt(self):
        c = Blowfish.new('pass', Blowfish.MODE_CBC, self.iv_blowfish)
        self.assertEqual(unpad(c.decrypt(self.encrypt_bf), c.block_size), b'sensitive information')

    def test_armor_dearmor(self):
        a = armor(self.encrypt_bf)
        self.assertEqual(dearmor(a), self.encrypt_bf)

    def test_aes(self):
        c = AES.new(aes_pad_key(b'pass'), AES.MODE_CBC, self.iv_aes)
        self.assertEqual(c.encrypt(pad(b'sensitive information', c.block_size)), self.encrypt_aes)

    def test_aes_pad(self):
        c = AES.new(aes_pad_key(b'secret'), AES.MODE_CBC, self.iv_aes)
        self.assertEqual(unpad(c.decrypt(self.encrypt_aes_padded), c.block_size), b'xxxxxxxxxxxxxxxx')


class FieldTests (TestCase):
    fixtures = ('employees',)

    def setUp(self):
        from django.db import connections
        c = connections['default'].cursor()
        c.execute('CREATE EXTENSION pgcrypto')

    def test_query(self):
        fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', 'employees.json')
        for obj in json.load(open(fixture_path, 'r')):
            if obj['model'] == 'core.employee':
                e = Employee.objects.get(ssn=obj['fields']['ssn'])
                self.assertEqual(e.pk, int(obj['pk']))
                self.assertEqual(e.salary, decimal.Decimal(obj['fields']['salary']))
                self.assertEqual(e.date_hired.isoformat(), obj['fields']['date_hired'])

    def test_decimal_lookups(self):
        self.assertEqual(Employee.objects.filter(salary=decimal.Decimal('75248.77')).count(), 1)
        self.assertEqual(Employee.objects.filter(salary__gte=decimal.Decimal('75248.77')).count(), 1)
        self.assertEqual(Employee.objects.filter(salary__gt=decimal.Decimal('75248.77')).count(), 0)
        self.assertEqual(Employee.objects.filter(salary__gte=decimal.Decimal('70000.00')).count(), 1)
        self.assertEqual(Employee.objects.filter(salary__lte=decimal.Decimal('70000.00')).count(), 1)
        self.assertEqual(Employee.objects.filter(salary__lt=decimal.Decimal('52000')).count(), 0)

    def test_date_lookups(self):
        self.assertEqual(Employee.objects.filter(date_hired='1999-01-23').count(), 1)
        self.assertEqual(Employee.objects.filter(date_hired__gte='1999-01-01').count(), 1)
        self.assertEqual(Employee.objects.filter(date_hired__gt='1981-01-01').count(), 2)

    def test_multi_lookups(self):
        self.assertEqual(Employee.objects.filter(date_hired__gt='1981-01-01', salary__lt=60000).count(), 1)

    def test_model_validation(self):
        obj = Employee(name='Invalid User', date_hired='2000-01-01', email='invalid')
        try:
            obj.full_clean()
            self.fail('Invalid employee object passed validation')
        except ValidationError, e:
            for f in ('salary', 'ssn', 'email'):
                self.assertIn(f, e.error_dict)

    def test_unique(self):
        with transaction.atomic():
            try:
                Employee.objects.create(name='Duplicate', date_hired='2000-01-01', email='johnson.sally@example.com')
                self.fail('Created duplicate email (should be unique).')
            except IntegrityError:
                pass
        # Make sure we can create another record with a NULL value for a unique field.
        e = Employee.objects.create(name='NULL Email', date_hired='2000-01-01', email=None)
        e = Employee.objects.get(pk=e.pk)
        self.assertIs(e.email, None)
        self.assertEqual(Employee.objects.filter(email__isnull=True).count(), 2)
