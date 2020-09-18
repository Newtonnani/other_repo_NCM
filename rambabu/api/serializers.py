from rambabu.models import *
from django.contrib.auth.models import User
from rest_framework import serializers

from django.contrib.auth.forms import PasswordResetForm
from django.conf import settings
from django.utils.translation import gettext as _


class CheckSerializer(serializers.Serializer):
    MID = serializers.CharField(required=True)
    ORDERID = serializers.CharField(required=True)

class ChangePasswordSerializer(serializers.Serializer):
    model = User

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'username')
    
    

class RegisterSerializer(serializers.ModelSerializer):
    
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'username', 'password','password2')
        extra_kwargs = {'password': {'write_only': True}}

    
    
    def create(self, validated_data):
        password = validated_data.pop('password')
        password2 = validated_data.pop('password2')

        if password != password2:
            raise serializers.ValidationError({'password': 'Passwords must match'})

        # user = User.objects.create_user(validated_data['username'],validated_data['email'],validated_data['password'])
        user = User(**validated_data)

        # user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user
    














# *********************************** DEBUG ************************************************** #

# class PasswordResetSerializer(serializers.Serializer):
#     username = serializers.CharField()
#     password_reset_form_class = PasswordResetForm
#     def validate_username(self, value):
#         self.reset_form = self.password_reset_form_class(data=self.initial_data)
#         if not self.reset_form.is_valid():
#             raise serializers.ValidationError(_('Error'))

#         ###### FILTER YOUR USER MODEL ######
#         if not User.objects.filter(username=value).exists():

#             raise serializers.ValidationError(_('Invalid username'))
#         return value

#     def save(self):
#         request = self.context.get('request')
#         opts = {
#             'use_https': request.is_secure(),
#             'from_email': getattr(settings, 'DEFAULT_FROM_EMAIL'),

#             ###### USE YOUR TEXT FILE ######
#             'email_template_name': 'example_message.txt',

#             'request': request,
#         }
#         self.reset_form.save(**opts)


# class PasswordResetSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ('username', 'password')
#         extra_kwargs = {'password': {'write_only': True}}

#     def create(self, validated_data):
#         username = validated_data.pop('username')
#         password = validated_data.pop('password')

#         if not User.objects.filter(username=username):
#             raise serializers.ValidationError({'Username': 'Username must match'})

#         # user = User.objects.create_user(validated_data['username'],validated_data['email'],validated_data['password'])
#         old_user = User.objects.get(username=username)
#         print(old_user)
#         user = User(**validated_data)

#         # user = User(**validated_data)
#         user.set_password(password)
#         user.save()
#         return user




# class UserSerializer(serializers.ModelSerializer):
#     password2 = serializers.CharField(write_only=True)

#     class Meta:
#         model = User
#         fields = ['first_name', 'last_name', 'email', 'username', 'password', 'password2',]
#         extra_kwargs = {'password': {'write_only': True}}

#     def create(self, validated_data):
#         password = validated_data.pop('password')
#         password2 = validated_data.pop('password2')

#         if password != password2:
#             raise serializers.ValidationError({'password': 'Passwords must match'})

#         user = User(**validated_data)
#         user.set_password(password)
#         user.save()
#         return user


# class AboutSerializer(serializers.ModelSerializer):
#     pass
