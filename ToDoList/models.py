from django.db import models


# Create your models here.
class User(models.Model):
    user_id = models.CharField(max_length=40, unique=True)
    password = models.CharField(max_length=300, null=False)
    email_address = models.EmailField(max_length=150, unique=True)
    user_uuid = models.CharField(max_length=36, primary_key=True)

    def __str__(self):
        return str(self.user_id)


class Task(models.Model):
    task_uuid = models.CharField(max_length=36, primary_key=True)
    task_title = models.CharField(max_length=200, null=False)
    task_description = models.TextField(max_length=800, null=True)
    task_done = models.BooleanField(default=False)
    task_owner = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.task_title)

