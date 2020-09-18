from rest_framework import viewsets
from .serializers import *
from rambabu.models import *
from rest_framework.permissions import AllowAny
from .permissons import IsLoggedInUserOrAdmin, IsAdminUser
from rest_framework import generics, permissions
from rest_framework.response import Response
from knox.models import AuthToken
from .serializers import UserSerializer, RegisterSerializer
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from django.contrib.auth import login
from rest_framework import permissions
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import (BasicAuthentication,SessionAuthentication)
from django.contrib.auth.decorators import login_required
from rest_framework.renderers import TemplateHTMLRenderer
from knox.auth import TokenAuthentication
from rest_framework.authtoken.views import ObtainAuthToken
import status
from rest_framework import status
from .serializers import ChangePasswordSerializer,CheckSerializer
from Paytm import Checksum
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, render_to_response
from django.contrib.auth.decorators import login_required

from rest_framework import mixins

import requests
import json
from django.conf import settings
from paytmchecksum import PaytmChecksum

# import paytmchecksum
# from user.serializers import UserSerializer
# Register API



class Check(APIView):
    # serializer_class = CheckSerializer
    def post(self, request):
        data = request.body
        paytmParams = {}
        
        paytmParams["MID"] = data["MID"]
        paytmParams["PAYTM_MERCHANT_KEY"] = data["PAYTM_MERCHANT_KEY"]
        # MERCHANT_KEY = settings.PAYTM_MERCHANT_KEY
        paytmParams["ORDERID"] = Checksum.__id_generator__()
        paytmChecksum = PaytmChecksum.generateSignature(paytmParams, paytmParams["PAYTM_MERCHANT_KEY"])
        # result = json.loads(paytmChecksum)
        return Response(str(paytmChecksum),status=status.HTTP_200_OK)
    

# class Donate(APIView):
#     renderer_classes = [TemplateHTMLRenderer]
#     template_name = 'rambabu/donate.html'

#     def get(self, request):
#         queryset = User.objects.all()
#         return Response({'profiles': str(queryset)})

def Donate(request):
    user = request.user
    MERCHANT_KEY = settings.PAYTM_MERCHANT_KEY
    MERCHANT_ID = settings.PAYTM_MERCHANT_ID
    CALLBACK_URL = settings.HOST_URL + settings.PAYTM_CLLBACK_URL + request.user.username +'/'
    order_id = Checksum.__id_generator__()

    if request.method == "GET":
        return render(request, 'rambabu/pay.html')
    try:
        bill_amount = int(request.POST['amount'])
    except:
        return render(request, 'rambabu/pay.html')


    if bill_amount:
        
        data_dict = {
            'MID': MERCHANT_ID,
            'ORDER_ID': order_id,
            'TXN_AMOUNT': str(bill_amount),
            'CUST_ID': "newton@gmail.com",
            'INDUSTRY_TYPE_ID': 'Retail',
            'WEBSITE': settings.PAYTM_WEBSITE,
            'CHANNEL_ID': 'WEB',
            'CALLBACK_URL': CALLBACK_URL,
        }
        param_dict = data_dict
        param_dict['CHECKSUMHASH'] = Checksum.generate_checksum(data_dict, MERCHANT_KEY)
        return render(request, 'rambabu/paytm.html', {'paytmdict':param_dict, 'user':user})



class About(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'rambabu/about.html'

    def get(self, request):
        queryset = User.objects.all()
        return Response({'profiles': str(queryset)})

class Initiate_Payment(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'rambabu/pay.html'


    def post(self, request):
        bill_amount = int(request.POST['amount'])
        user = request.user
        MERCHANT_KEY = settings.PAYTM_MERCHANT_KEY
        MERCHANT_ID = settings.PAYTM_MERCHANT_ID
        CALLBACK_URL = settings.HOST_URL + settings.PAYTM_CLLBACK_URL + request.user.username + '/'
        order_id = Checksum.__id_generator__()
        

        if self.bill_amount:
            data_dict = {
                'MID': MERCHANT_ID,
                'ORDER_ID': order_id,
                'TXN_AMOUNT': str(bill_amount),
                # 'CUST_ID': request.user.email,
                'CUST_ID': 'newton102@gmail.com',
                'INDUSTRY_TYPE_ID': 'Retail',
                'WEBSITE': settings.PAYTM_WEBSITE,
                'CHANNEL_ID': 'WEB',
                'CALLBACK_URL': CALLBACK_URL,
            }
            param_dict = data_dict
            param_dict['CHECKSUMHASH'] = Checksum.generate_checksum(data_dict, MERCHANT_KEY)
            return render(request, 'rambabu/paytm.html', {'paytmdict':param_dict, 'user':user})
            
        return HttpResponse("Bill Amount Could not find.")

# recent_sermons.html

class Recent_Sermons(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'rambabu/recent_sermons.html'


    def get(self, request):
        queryset = User.objects.all()
        return Response({'profiles': str(queryset)})

class Upcoming_Events(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'rambabu/upcoming_events.html'


    def get(self, request):
        queryset = User.objects.all()
        return Response({'profiles': str(queryset)})

class Contact_Us(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'rambabu/contact_us.html'


    def get(self, request):
        queryset = User.objects.all()
        return Response({'profiles': str(queryset)})



class Power_Houes_Details(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'rambabu/power_house_details.html'


    def get(self, request):
        queryset = User.objects.all()
        return Response({'profiles': str(queryset)})

class Home(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'rambabu/index.html'


    def get(self, request):
        queryset = User.objects.all()
        return Response({'profiles': str(queryset)})



class RegisterAPI(generics.ListCreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = (permissions.AllowAny,)


    def get(self, request, *args, **kwargs):
        return Response(status=status.HTTP_200_OK)

        

    def post(self, request, *args, **kwargs):
        self.user = {"first_name": "",
        "last_name": "",
        "email": "",
        "username": ""}
        serializer = self.get_serializer(data=request.data)
        # print(serializer)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            # print(user)
            token = Token.objects.get(user=user).key
            # self.user["token"] = token
            return Response({"user": UserSerializer(user, context=self.get_serializer_context()).data,"token":token,"msg":"Successfully Created User"})

        except serializers.ValidationError as msg:
            return Response({"user": self.user,"token":"","msg":str(msg)},status=status.HTTP_200_OK)

# class RegisterAPI(generics.GenericAPIView):
#     serializer_class = RegisterSerializer
#     permission_classes = (permissions.AllowAny,)
#     http_method_names = ['get', 'head', 'post']

#     def get(self, request, *args, **kwargs):
#         return Response(status=status.HTTP_200_OK)

        

#     def post(self, request, *args, **kwargs):

#         self.user = {"first_name": "",
#         "last_name": "",
#         "email": "",
#         "username": ""}
#         serializer = self.get_serializer(data=request.data)
#         # print(serializer)
#         try:
#             serializer.is_valid(raise_exception=True)
#             user = serializer.save()
#             # print(user)
#             token = Token.objects.get(user=user).key
#             # self.user["token"] = token
#             return Response({"user": UserSerializer(user, context=self.get_serializer_context()).data,"token":token,"msg":"Successfully Created User"})

#         except serializers.ValidationError as msg:
#             return Response({"user": self.user,"token":"","msg":str(msg)},status=status.HTTP_200_OK)



       
        




class LoginAPI(KnoxLoginView):
    authentication_classes = [BasicAuthentication,TokenAuthentication]
    # authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.AllowAny,)

    
    def get(self, request):
        # queryset = User.objects.all()
        # return Response(status=status.HTTP_200_OK,headers={'Content-Type': 'application/x-www-form-urlencoded', 'Accept':'application/json; charset=utf-8'})
        return Response({},status=status.HTTP_200_OK)

    

    def post(self, request, format=None):
        self.content = {"expiry":"","token":""}
        serializer = AuthTokenSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            login(request, user)
            print(user)
            # return Response(serializer.data)
            return super(LoginAPI, self).post(request, format=None)
        except serializers.ValidationError as msg:
            return Response(self.content,status=status.HTTP_200_OK)

    # def get(self, request):
    #     # queryset = User.objects.all()
    #     return Response(status=status.HTTP_200_OK,headers={'Content-Type': 'application/x-www-form-urlencoded', 'Accept':'application/json; charset=utf-8'})



class CustomAuthToken(ObtainAuthToken):

    def get(self, request, *args, **kwargs):
        queryset = User.objects.all()
        return Response(status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })




class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_200_OK)









# ***********************************  reset password ********************************
# from django.http import Http404
# from django.utils.translation import gettext as _
# from rest_framework import serializers
# from rest_framework.decorators import api_view, permission_classes

# from rest_registration.api.serializers import PasswordConfirmSerializerMixin
# from rest_registration.decorators import (
#     api_view_serializer_class,
#     api_view_serializer_class_getter
# )
# from rest_registration.exceptions import UserNotFound
# from rest_registration.notifications.email import (
#     send_verification_notification
# )
# from rest_registration.notifications.enums import NotificationType
# from rest_registration.settings import registration_settings
# from rest_registration.utils.responses import get_ok_response
# from rest_registration.utils.users import (
#     get_user_by_verification_id,
#     get_user_verification_id
# )
# from rest_registration.utils.validation import (
#     run_validators,
#     validate_password_with_user_id,
#     validate_user_password_confirm
# )
# from rest_registration.utils.verification import verify_signer_or_bad_request
# from rest_registration.verification import URLParamsSigner


# class ResetPasswordSigner(URLParamsSigner):
#     SALT_BASE = 'reset-password'
#     USE_TIMESTAMP = True

#     def get_base_url(self):
#         return registration_settings.RESET_PASSWORD_VERIFICATION_URL

#     def get_valid_period(self):
#         return registration_settings.RESET_PASSWORD_VERIFICATION_PERIOD

#     def _calculate_salt(self, data):
#         if registration_settings.RESET_PASSWORD_VERIFICATION_ONE_TIME_USE:
#             user = get_user_by_verification_id(
#                 data['user_id'], require_verified=False)
#             user_password_hash = user.password
#             # Use current user password hash as a part of the salt.
#             # If the password gets changed, then assume that the change
#             # was caused by previous password reset and the signature
#             # is not valid anymore because changed password hash implies
#             # changed salt used when verifying the input data.
#             salt = '{self.SALT_BASE}:{user_password_hash}'.format(
#                 self=self, user_password_hash=user_password_hash)
#         else:
#             salt = self.SALT_BASE
#         return salt


# [docs]@api_view_serializer_class_getter(
#     lambda: registration_settings.SEND_RESET_PASSWORD_LINK_SERIALIZER_CLASS)
# @api_view(['POST'])
# @permission_classes(registration_settings.NOT_AUTHENTICATED_PERMISSION_CLASSES)
# def send_reset_password_link(request):
#     '''
#     Send email with reset password link.
#     '''
#     if not registration_settings.RESET_PASSWORD_VERIFICATION_ENABLED:
#         raise Http404()
#     serializer_class = registration_settings.SEND_RESET_PASSWORD_LINK_SERIALIZER_CLASS  # noqa: E501
#     serializer = serializer_class(
#         data=request.data,
#         context={'request': request},
#     )
#     serializer.is_valid(raise_exception=True)
#     if registration_settings.RESET_PASSWORD_FAIL_WHEN_USER_NOT_FOUND:
#         success_message = _("Reset link sent")
#     else:
#         success_message = _("Reset link sent if the user exists in database")
#     user = serializer.get_user_or_none()
#     if not user:
#         if registration_settings.RESET_PASSWORD_FAIL_WHEN_USER_NOT_FOUND:
#             raise UserNotFound()
#         return get_ok_response(success_message)
#     signer = ResetPasswordSigner({
#         'user_id': get_user_verification_id(user),
#     }, request=request)

#     template_config_data = registration_settings.RESET_PASSWORD_VERIFICATION_EMAIL_TEMPLATES  # noqa: E501
#     notification_data = {
#         'params_signer': signer,
#     }
#     send_verification_notification(
#         NotificationType.RESET_PASSWORD_VERIFICATION, user, notification_data,
#         template_config_data)

#     return get_ok_response(success_message)



# class ResetPasswordSerializer(  # pylint: disable=abstract-method
#         PasswordConfirmSerializerMixin,
#         serializers.Serializer):
#     user_id = serializers.CharField(required=True)
#     timestamp = serializers.IntegerField(required=True)
#     signature = serializers.CharField(required=True)
#     password = serializers.CharField(required=True)

#     def has_password_confirm_field(self):
#         return registration_settings.RESET_PASSWORD_SERIALIZER_PASSWORD_CONFIRM

#     def validate(self, attrs):
#         validators = [
#             validate_password_with_user_id,
#         ]
#         if self.has_password_confirm_field():
#             validators.append(validate_user_password_confirm)
#         run_validators(validators, attrs)
#         return attrs


# [docs]@api_view_serializer_class(ResetPasswordSerializer)
# @api_view(['POST'])
# @permission_classes(registration_settings.NOT_AUTHENTICATED_PERMISSION_CLASSES)
# def reset_password(request):
#     '''
#     Reset password, given the signature and timestamp from the link.
#     '''
#     process_reset_password_data(
#         request.data, serializer_context={'request': request})
#     return get_ok_response(_("Reset password successful"))



# def process_reset_password_data(input_data, serializer_context=None):
#     if serializer_context is None:
#         serializer_context = {}
#     if not registration_settings.RESET_PASSWORD_VERIFICATION_ENABLED:
#         raise Http404()
#     serializer = ResetPasswordSerializer(
#         data=input_data,
#         context=serializer_context,
#     )
#     serializer.is_valid(raise_exception=True)

#     data = serializer.validated_data.copy()
#     password = data.pop('password')
#     data.pop('password_confirm', None)
#     signer = ResetPasswordSigner(data)
#     verify_signer_or_bad_request(signer)

#     user = get_user_by_verification_id(data['user_id'], require_verified=False)
#     user.set_password(password)
#     user.save()
# *********************************** DEBUG *****************************************#


# class PasswordAPI(generics.GenericAPIView):
#     serializer_class = PasswordResetSerializer

#     def post(self, request, *args, **kwargs):
#         self.user = {"username": ""}
#         serializer = self.get_serializer(data=request.data)
#         # print(serializer)
#         try:
#             serializer.is_valid(raise_exception=True)
#             user = serializer.save()
#             # print(user)
#             # token = Token.objects.get(user=user).key
#             # self.user["token"] = token
#             return Response({"user": UserSerializer(user, context=self.get_serializer_context()).data,"token":token,"msg":"Password Successful reset "})

#         except serializers.ValidationError as msg:
#             return Response({"user": self.user,"token":"","msg":str(msg)},status=status.HTTP_200_OK)


# class UserCreateAPIView(viewsets.ModelViewSet):
#     serializer_class = UserSerializer
#     queryset = User.objects.all()

#     # Add this code block
#     def get_permissions(self):
#         permission_classes = []
#         if self.action == 'create':
#             permission_classes = [AllowAny]
#         elif self.action == 'retrieve' or self.action == 'update' or self.action == 'partial_update':
#             permission_classes = [IsLoggedInUserOrAdmin]
#         elif self.action == 'list' or self.action == 'destroy':
#             permission_classes = [IsAdminUser]
#         return [permission() for permission in permission_classes]



# class ExampleView(APIView):
#     authentication_classes = [SessionAuthentication, BasicAuthentication]
#     permission_classes = [IsAuthenticated]

#     def get(self, request, format=None):
#         content = {
#             'user': str(request.user),  # `django.contrib.auth.User` instance.
#             'auth': str(request.auth),  # None
#         }
#         return Response(content)

# class LoginAPI(KnoxLoginView):
#     permission_classes = (permissions.AllowAny,)

#     def post(self, request, format=None):
#         self.content = {'user':'','msg':'','token':''}
#         serializer = AuthTokenSerializer(data=request.data)
#         try:
#             serializer.is_valid(raise_exception=True)
#             user = serializer.validated_data['user']
#             login(request, user)
#             # print(type(super(LoginAPI, self).post(request, format=None)))
#             # print(super(LoginAPI, self).post(request, format=None).render)
#             # print(super(LoginAPI, self).post(request, format=None).getvalue)

#             content = {
#                 'user': str(request.user),  # `django.contrib.auth.User` instance.
#                 # 'auth': str(request.auth),  # None
#                 'msg': "Successful logged in"
#             }
#             for user in User.objects.all():
#                 token = Token.objects.get_or_create(user=user)[0]

#             # token = Token.objects.get(user=user).key
#             content["token"] = str(token)
            
#             return Response(content)
            
#             # return super(LoginAPI, self).post(request, format=None)
#         except serializers.ValidationError as msg:
#             self.content["msg"] = str(msg)
#             return Response(self.content,status=status.HTTP_200_OK)


# class LoginAPI(APIView):
#     authentication_classes = (TokenAuthentication,)
#     permission_classes = (IsAuthenticated,)

#     def get(self, request, format=None):
#         content = {
#             'foo': 'bar'
#         }
#         return Response(content)

# class LoginAPI(APIView):
#     permission_classes = (permissions.AllowAny,)

#     authentication_classes = [SessionAuthentication, BasicAuthentication]
#     permission_classes = [IsAuthenticated]

#     def get(self, request, format=None):
#         print(" Hello World "*10)
#         self.content = {'user':'','msg':'','token':''}
#         serializer = AuthTokenSerializer(data=request.data)
#         try:
#             serializer.is_valid(raise_exception=True)
#             # print(serializer)
#             self.content['user'] = str(request.user)
#             self.content['msg'] = "Successful logged in"

#             # user = serializer.validated_data['user']
#             # login(request, user)

#             # user = serializer.save()
#             # print(user)
#             # for user in User.objects.all():
#             #     token = Token.objects.get_or_create(user=user)[0]

#             # # token = Token.objects.get(user=user).key
#             # self.content["token"] = str(token)

#             content = {
#                 'user': str(request.user),  # `django.contrib.auth.User` instance.
#                 # 'auth': str(request.auth),  # None
#                 'msg': "Successful logged in"
#             }
#             return Response(self.content)

#         except serializers.ValidationError as msg:
#             self.content['msg'] = str(msg)
#             return Response(self.content, status=status.HTTP_200_OK)

    
    # def post(self, request, format=None):
    #     # self.cred = {"expiry":"","token":""}
    #     serializer = AuthTokenSerializer(data=request.data)

    #     serializer.is_valid(raise_exception=True)
    #     user = serializer.validated_data['user']
    #     login(request, user)
    #     # print(super(LoginAPI, self))
    #     return super(LoginAPI, self).post(request, format=None)

        # except serializers.ValidationError as msg:
        #     self.cred["msg"] = str(msg)
        #     return Response(self.cred,status=status.HTTP_200_OK)





         # serializer.is_valid(raise_exception=True)
        # user = serializer.save()
        #     # print(user)
        # return Response({"user": UserSerializer(user, context=self.get_serializer_context()).data,"msg":"Successfully Created User"},status=status.HTTP_200_OK)

            # if str(msg) == "A user with that username already exists":
            #     print("Hello WOrld")
            #     return Response(
            #         {'ValidationError': str(msg)},
            #         status=status.HTTP_200_OK
            #     )
            # else:
            #     return Response(
            #         {'ValidationError': str(msg)},
            #     status=status.HTTP_400_BAD_REQUEST
            #     )
        # except Exception as e:
            # print(e)
        # user = serializer.save()



# class Donate(APIView):
#     renderer_classes = [TemplateHTMLRenderer]
#     template_name = 'rambabu/donate.html'


#     def get(self, request):
#         queryset = User.objects.all()
#         return Response({'profiles': queryset})