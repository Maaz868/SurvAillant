# webapp/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import Group, Permission


class CustomUser(AbstractUser):
    is_admin = models.BooleanField(default=False)
    is_user_approved = models.BooleanField(default=False)
    # Add related_name to avoid clashes with auth.User
    groups = models.ManyToManyField(Group, blank=True, related_name='customuser_set', related_query_name='customuser')
    user_permissions = models.ManyToManyField(Permission, blank=True, related_name='customuser_set', related_query_name='customuser')

class Packet(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.CharField(max_length=15)
    destination_ip = models.CharField(max_length=20)
    protocol = models.CharField(max_length=10, default='')
    # Add more fields as needed
