import datetime
import decimal
import json
import os
import unittest

from cryptography.hazmat.primitives.ciphers.algorithms import AES
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import connections, transaction
from django.db.models import Value
from django.db.models.fields import CharField
from django.db.models.functions import Concat
from django.db.utils import IntegrityError
from django.test import TestCase

from pgcrypto import __version__, armor, dearmor, pad, unpad
from pgcrypto.fields import BaseEncryptedField
from pgcrypto.functions import Decrypt, Encrypt

from .models import Employee


class CryptoTests(unittest.TestCase):
    def setUp(self):
        # This is the expected AES-encrypted value, according to the following query:
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
        f = BaseEncryptedField(cipher="aes", key=b"pass")
        self.assertEqual(
            f.encrypt(pad(b"sensitive information", f.block_size)), self.encrypt_aes
        )

    def test_decrypt(self):
        f = BaseEncryptedField(cipher="aes", key=b"pass")
        self.assertEqual(
            unpad(f.decrypt(self.encrypt_aes), f.block_size), b"sensitive information"
        )

    def test_armor_dearmor(self):
        a = armor(self.encrypt_aes)
        self.assertEqual(dearmor(a), self.encrypt_aes)

    def test_aes(self):
        f = BaseEncryptedField(cipher="aes", key=b"pass")
        self.assertEqual(
            f.encrypt(pad(b"sensitive information", f.block_size)), self.encrypt_aes
        )

    def test_aes_pad(self):
        f = BaseEncryptedField(cipher="aes", key=b"secret")
        self.assertEqual(
            unpad(f.decrypt(self.encrypt_aes_padded), f.block_size), b"xxxxxxxxxxxxxxxx"
        )


class FieldTests(TestCase):
    fixtures = ("employees",)

    def setUp(self):
        # Normally, you would use django.contrib.postgres.operations.CryptoExtension in
        # migrations.
        c = connections["default"].cursor()
        c.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    def test_query(self):
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "employees.json"
        )
        for obj in json.load(open(fixture_path, "r")):
            if obj["model"] == "core.employee":
                e = Employee.objects.get(ssn=obj["fields"]["ssn"])
                self.assertEqual(e.pk, int(obj["pk"]))
                self.assertEqual(e.age, 42)
                self.assertEqual(e.salary, decimal.Decimal(obj["fields"]["salary"]))
                self.assertEqual(e.date_hired.isoformat(), obj["fields"]["date_hired"])

    def test_decimal_lookups(self):
        self.assertEqual(
            Employee.objects.filter(salary=decimal.Decimal("75248.77")).count(), 1
        )
        self.assertEqual(
            Employee.objects.filter(salary__gte=decimal.Decimal("75248.77")).count(), 1
        )
        self.assertEqual(
            Employee.objects.filter(salary__gt=decimal.Decimal("75248.77")).count(), 0
        )
        self.assertEqual(
            Employee.objects.filter(salary__gte=decimal.Decimal("70000.00")).count(), 1
        )
        self.assertEqual(
            Employee.objects.filter(salary__lte=decimal.Decimal("70000.00")).count(), 1
        )
        self.assertEqual(
            Employee.objects.filter(salary__lt=decimal.Decimal("52000")).count(), 0
        )

    def test_date_lookups(self):
        self.assertEqual(Employee.objects.filter(date_hired="1999-01-23").count(), 1)
        self.assertEqual(
            Employee.objects.filter(date_hired__gte="1999-01-01").count(), 1
        )
        self.assertEqual(
            Employee.objects.filter(date_hired__gt="1981-01-01").count(), 2
        )

    def test_multi_lookups(self):
        self.assertEqual(
            Employee.objects.filter(
                date_hired__gt="1981-01-01", salary__lt=60000
            ).count(),
            1,
        )

    def test_model_validation(self):
        obj = Employee(name="Invalid User", date_hired="2000-01-01", email="invalid")
        try:
            obj.full_clean()
            self.fail("Invalid employee object passed validation")
        except ValidationError as e:
            for f in ("salary", "email"):
                self.assertIn(f, e.error_dict)

    def test_blank(self):
        obj = Employee.objects.create(
            name="Test User", date_hired=datetime.date.today(), email="test@example.com"
        )
        self.assertEqual(obj.ssn, "")
        obj.refresh_from_db()
        self.assertEqual(obj.ssn, "")
        self.assertEqual(Employee.objects.filter(ssn="").count(), 1)

    def test_exclude_update(self):
        obj = Employee.objects.create(
            name="Test User",
            date_hired=datetime.date.today(),
            email="test@example.com",
        )
        Employee.objects.exclude(ssn="666-27-9811").update(ssn="666-27-9811")
        obj.refresh_from_db()
        self.assertEqual(obj.ssn, "666-27-9811")
        Employee.objects.exclude(age=30).update(age=30)
        obj.refresh_from_db()
        self.assertEqual(obj.age, 30)

    def test_in(self):
        qs = Employee.objects.filter(ssn__in=["999-05-6728", "666-27-9811"])
        self.assertEqual(qs.count(), 2)
        self.assertEqual(
            list(qs.values_list("name", flat=True)),
            ["John Smith", "Sally Johnson"],
        )
        qs = Employee.objects.filter(salary__in=[52000])
        self.assertEqual(qs.count(), 1)

    def test_unique(self):
        with transaction.atomic():
            try:
                Employee.objects.create(
                    name="Duplicate",
                    date_hired="2000-01-01",
                    email="johnson.sally@example.com",
                )
                self.fail("Created duplicate email (should be unique).")
            except IntegrityError:
                pass
        # Make sure we can create another record with a NULL value for a unique field.
        e = Employee.objects.create(
            name="NULL Email", date_hired="2000-01-01", email=None
        )
        e = Employee.objects.get(pk=e.pk)
        self.assertIs(e.email, None)
        self.assertEqual(Employee.objects.filter(email__isnull=True).count(), 2)

    def test_auto_now(self):
        e = Employee.objects.create(name="Joe User", ssn="12345", salary=42000)
        self.assertEqual(e.date_hired, datetime.date.today())
        self.assertEqual(e.date_modified, Employee.objects.get(pk=e.pk).date_modified)

    def test_formfields(self):
        expected = {
            "name": forms.CharField,
            "age": forms.IntegerField,
            "ssn": forms.CharField,
            "salary": forms.DecimalField,
            "date_hired": forms.DateField,
            "email": forms.EmailField,
            "date_modified": forms.DateTimeField,
        }
        actual = {
            f.name: type(f.formfield())
            for f in Employee._meta.fields
            if not f.primary_key
        }
        self.assertEqual(actual, expected)

    def test_raw_versioned(self):
        e = Employee.objects.get(ssn="666-27-9811")
        version_check = "Version: django-pgcrypto %s" % __version__
        raw_ssn = e.raw.ssn
        # Check that the correct version was stored.
        self.assertIn(version_check, raw_ssn)
        # Check that SECRET_KEY was used by default.
        f = BaseEncryptedField(key=settings.SECRET_KEY)
        self.assertEqual(f.to_python(raw_ssn), e.ssn)
        # Check that trying to decrypt with a bad key is (probably) gibberish.
        with self.assertRaises(UnicodeDecodeError):
            f = BaseEncryptedField(key="badkeyisaverybadkey")
            f.to_python(raw_ssn)

    def test_bulk_update(self):
        employees_to_update = Employee.objects.filter(
            ssn__in=["999-05-6728", "666-27-9811"]
        )
        for employee in employees_to_update:
            employee.salary += 10000

        Employee.objects.bulk_update(employees_to_update, ["salary"])

        updated_employee_1 = Employee.objects.get(ssn="999-05-6728")
        updated_employee_2 = Employee.objects.get(ssn="666-27-9811")

        self.assertEqual(updated_employee_1.salary, decimal.Decimal("62000.00"))
        self.assertEqual(updated_employee_2.salary, decimal.Decimal("85248.77"))

    def test_encrypt_function(self):
        employee = Employee.objects.annotate(
            encrypted_name=Encrypt("name"),
            roundtrip_name=Decrypt(Encrypt("name")),
        ).get(name="John Smith")
        expected = (
            "-----BEGIN PGP MESSAGE-----\n\n"
            "S3CgYGeFb6yTyQZVW00n9Q==\n"
            "=IuEt\n"
            "-----END PGP MESSAGE-----\n"
        )
        self.assertEqual(employee.name, "John Smith")
        self.assertEqual(employee.encrypted_name, expected)
        self.assertEqual(employee.roundtrip_name, employee.name)

    def test_decrypt_function(self):
        employee = Employee.objects.annotate(value=Decrypt("ssn")).get(
            ssn="999-05-6728"
        )
        self.assertEqual(employee.value, "999-05-6728")

    def test_concat_decrypt(self):
        employee = Employee.objects.annotate(
            value=Concat(
                Decrypt("ssn"), Value(" - "), Decrypt("age"), output_field=CharField()
            )
        ).get(ssn="999-05-6728")
        self.assertEqual(employee.value, "999-05-6728 - 42")

    def test_exact(self):
        employee = Employee.objects.filter(email__exact="johnson.sally@example.com").get()
        self.assertEqual(employee.email, "johnson.sally@example.com")

    def test_iexact(self):
        employee = Employee.objects.filter(email__iexact="Johnson.saLly@ExamPle.cOm").get()
        self.assertEqual(employee.email, "johnson.sally@example.com")

    def test_contains(self):
        employee = Employee.objects.filter(email__contains="sal").get()
        self.assertEqual(employee.email, "johnson.sally@example.com")

    def test_icontains(self):
        employee = Employee.objects.filter(email__icontains="SAL").get()
        self.assertEqual(employee.email, "johnson.sally@example.com")

    def test_startswith(self):
        employee = Employee.objects.filter(email__startswith="john").get()
        self.assertEqual(employee.email, "johnson.sally@example.com")

    def test_istartswith(self):
        employee = Employee.objects.filter(email__istartswith="JOHN").get()
        self.assertEqual(employee.email, "johnson.sally@example.com")

    def test_endswith(self):
        employee = Employee.objects.filter(email__endswith="com").get()
        self.assertEqual(employee.email, "johnson.sally@example.com")

    def test_iendswith(self):
        employee = Employee.objects.filter(email__iendswith="COM").get()
        self.assertEqual(employee.email, "johnson.sally@example.com")
