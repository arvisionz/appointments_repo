from __future__ import unicode_literals

from django.db import models
from ..login_and_reg_app.models import User

class Appointment(models.Model):
    task = models.CharField(max_length=1000)
    date = models.CharField(max_length=1000)
    time = models.CharField(max_length=45)
    status = models.CharField(max_length=45, default='pending')
    user = models.ForeignKey(User, related_name='appointments')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
