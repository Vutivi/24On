from django.db import models
from django.contrib.auth.models import AbstractUser, Group
from django.db.models import Q

# Create your models here.
class User(AbstractUser):
    date_of_birth = models.DateField()
    phone_number = models.CharField(max_length=30)

    REQUIRED_FIELDS = ['date_of_birth', 'phone_number', 'email', 'first_name',
                       'last_name']

    def all_clients(self):
        """
        Returns all patients relevant for a given user.
        If the user is a doctor:
            Returns all patients with active appointments with the doctor.
        If the user is a patient:
            Returns themself.
        If the user is an admin:
            Returns all patients in the database.
        :return:
        """
        if self.is_superuser:
            # Admins and doctors can see all users as patients.
            return Group.objects.get(name='Client').user_set.all()
        else:
            # Users can only see themselves.
            return User.objects.filter(pk=self.pk)

    def can_edit_user(self, user):
        return user == self      \
            or self.is_superuser \
            or user.is_client()


    def is_client(self):
        """
        :return: True if the user belongs to the Patient group.
        """
        return self.is_in_group("Client")

    def is_in_group(self, group_name):
        """
        :param group_name: The group within which to check membership.
        :return: True if the user is a member of the group provided.
        """
        try:
            return (Group.objects.get(name=group_name)
                         .user_set.filter(pk=self.pk).exists())
        except ValueError:
            return False

    def group(self):
        return self.groups.first()
