from .views import RegisterAPI
from django.urls import path, include

from knox import views as knox_views
from .views import (
    LoginAPI, 
    ChangePasswordView,
    Home,
    About,
    Power_Houes_Details,
    Recent_Sermons,
    Upcoming_Events,
    Contact_Us,
    Initiate_Payment,
    Donate,
    Check)
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from .views import CustomAuthToken

from rest_framework.authtoken import views as authviews

urlpatterns = [
    path('register/', RegisterAPI.as_view(), name='api_register'),
    path('auth/login/', LoginAPI.as_view(), name='api_login'),
    path('auth/logout/', knox_views.LogoutView.as_view(), name='api_logout'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),
    path('home/',Home.as_view(), name='api_home'),
    path('about/',About.as_view(), name='api_about'),
    # path('donate/',Donate.as_view(), name='api_donate'),
    path('check/',Check.as_view(), name='api_check'),
    path('donate/', Donate, name='api_donate'),
    path('power_house/',Power_Houes_Details.as_view(), name='api_powerhousedetails'),
    path('sermons/',Recent_Sermons.as_view(), name='api_recentsermons'),
    path('events/',Upcoming_Events.as_view(), name='api_upcomingevents'),
    path('contact/',Contact_Us.as_view(), name='api_contactus'),
    # path('initiate-payment/',Initiate_Payment.as_view(), name='api_initiatepayment'),
]




# ************************************* DEBUG ********************************************* #

# urlpatterns = [
#     path('login/', LoginAPI.as_view(), name='login'),
#     path('logout/', knox_views.LogoutView.as_view(), name='logout'),
#     path('logoutall/', knox_views.LogoutAllView.as_view(), name='logoutall'),
# ]
# from django.urls import path, include
# from rest_framework import routers
# from . views import *

# router = routers.DefaultRouter()
# router.register(r'register', UserCreateAPIView)

# urlpatterns = [
#     path('', include(router.urls)),
#     path('auth/', include('rest_auth.urls')),
# ]


    


    # path('password_reset/', PasswordAPI.as_view(), name='api_password_reset'),
    # path('api-token-auth/', views.obtain_auth_token, name='api_token_auth'),
    # path('api/logoutall/', knox_views.LogoutAllView.as_view(), name='api_logoutall'),