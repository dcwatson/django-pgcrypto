Example Usage
=============

    from django.db import models
    import pgcrypto
    
    class Employee (models.Model):
        first_name = models.CharField(max_length=100)
        last_name = models.CharField(max_length=100)
        ssn = pgcrypto.EncryptedTextField()
        pay_rate = pgcrypto.EncryptedDecimalField()
