from django.db import models

import pgcrypto


class Employee(models.Model):
    name = models.CharField(max_length=200)
    age = pgcrypto.EncryptedIntegerField(default=42)
    ssn = pgcrypto.EncryptedCharField("SSN", versioned=True, blank=True)
    salary = pgcrypto.EncryptedDecimalField()
    date_hired = pgcrypto.EncryptedDateField(
        cipher="aes", key="datekey", auto_now_add=True
    )
    email = pgcrypto.EncryptedEmailField(unique=True, null=True)
    date_modified = pgcrypto.EncryptedDateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    @property
    def raw(self):
        return RawEmployee.objects.get(pk=self.pk)


class RawEmployee(models.Model):
    name = models.CharField(max_length=200)
    age = models.TextField()
    ssn = models.TextField()
    salary = models.TextField()
    date_hired = models.TextField()
    email = models.TextField(null=True)
    date_modified = models.TextField()

    class Meta:
        db_table = "testapp_employee"
        managed = False
