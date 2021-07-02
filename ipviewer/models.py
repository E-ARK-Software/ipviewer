from django.contrib.auth.models import User
from django.db import models


class DetectedInformationPackage(models.Model):
    id = models.AutoField(primary_key=True)
    task_id = models.CharField(max_length=200)
    information_package = models.CharField(max_length=200)
    title = models.CharField(max_length=500)
    created = models.DateTimeField(auto_now_add=True, blank=True)
    ip_base_dir = models.CharField(max_length=500)
    ip_filename = models.CharField(max_length=500)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    selected = models.BooleanField(unique=False, default=False)
