from .models import Profile 
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
# requires to define two functions authenticate and get_user
from django.contrib.auth.models import User

class PasswordlessAuthBackend(ModelBackend):  

    def authenticate( user=None):
        try:
            Prof = Profile.objects.get(user=User.objects.get(username=user).id)
            # print("el del auth es"+str(Prof))
            return Prof.user
        except Profile.DoesNotExist:
            return None

        return None

    # def get_user( user):
    #     try:
    #         print("el del get es"+Profile.objects.get(user=user))
    #         return Profile.objects.get(user=User.objects.get(username=user).id)
    #     except Profile.DoesNotExist:
    #         return None