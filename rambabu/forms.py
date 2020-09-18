from django.contrib.auth.forms import UserCreationForm
from django.forms import ModelForm, forms
from .models import *

class CreateUserForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name','password1', 'password2']

    def clean_username(self):
        user = self.cleaned_data['username']
        try:
            match = User.objects.get(username=user)
        except:
            return self.cleaned_data['username']
        raise forms.ValidationError('Username already exists')

    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            mt = User.objects.get(email=email)
        except:
            return self.cleaned_data['email']
        raise forms.ValidationError('Email already exists')

# class UserProfileForm(ModelForm):
#
#     class Meta:
#         model = ExtendUser
#         fields = ('mobile_number','address','member_type', 'power_member_check', 'power_member_location')