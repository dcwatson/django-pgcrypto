from django.db import models
import pgcrypto

class Employee (models.Model):
    name = models.CharField(max_length=200)
    ssn = pgcrypto.EncryptedCharField()
    salary = pgcrypto.EncryptedDecimalField()

    def __unicode__(self):
        return self.name
