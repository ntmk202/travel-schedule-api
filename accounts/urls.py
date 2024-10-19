from django.urls import path
from .views import *

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('forgot-password/', ForgotPasswordAPIView.as_view(), name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', ResetPasswordAPIView.as_view(), name='reset_password'),
    path('profile/', ProfileAPIView.as_view(), name='profile'),
    path('update-profile/', UpdateProfileAPIView.as_view(), name='update_profile'),
    path('change-password/', ChangePasswordAPIView.as_view(), name='change_password'),
]
