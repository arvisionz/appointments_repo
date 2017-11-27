
from __future__ import unicode_literals
from django.db import models
import re, bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class UserManager(models.Manager):
    def login(self, postData):
        user = self.filter(email=postData['email'])
        response_to_views = {}
        if not user:
            response_to_views['status'] = False
            response_to_views['errors'] = 'Email address not valid'

        else:
            if bcrypt.checkpw(postData['password'].encode(), user[0].password.encode()):
                response_to_views['status'] = True
                response_to_views['user'] = user[0]

            else:
                response_to_views['status'] = False
                response_to_views['errors'] = 'Email/password combination not valid'

        return response_to_views

    def register(self, postData):
        errors = []
        if len(postData['name']) < 3:
            errors.append('Name must be at least 3 characters long!')
        if len(postData['email']) < 1:
            errors.append('Email field cannot be empty')
        if not EMAIL_REGEX.match(postData['email']):
            errors.append("Enter a valid email")
        if len(postData['password']) < 8:
            errors.append('Password must contain at least 8 characters')
        if postData['password'] != postData['pwd_conf']:
            errors.append('Passwords do not match')
        if self.filter(email=postData['email']):
            errors.append('Email already in use')

        response_to_views = {}
        if len(errors) == 0:
            hashed_password = bcrypt.hashpw(postData['password'].encode(), bcrypt.gensalt())
            user = self.create(name=postData['name'], email=postData['email'], password=hashed_password)
            response_to_views['user'] = user
            response_to_views['status'] = True

        else:
            response_to_views['errors'] = errors
            response_to_views['status'] = False

        return response_to_views
class User(models.Model):
    name = models.CharField(max_length=45)
    email = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()
      
