from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import authenticate, login, logout
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .models import User

class RegisterAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already registered."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, email=email, password=password)
        return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)

class LoginAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, email=email, password=password)
        
        if user:
            login(request, user)
            return Response({"message": "Logged in successfully."}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)

class ForgotPasswordAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "Email not found."}, status=status.HTTP_400_BAD_REQUEST)
        
        token = PasswordResetTokenGenerator().make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = f"http://frontend_url/reset-password/{uid}/{token}/"
        send_mail(
            'Password Reset Request',
            f'Click the link to reset your password: {reset_link}',
            'from@example.com',
            [email],
            fail_silently=False,
        )
        return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)

class ResetPasswordAPIView(APIView):
    def post(self, request, uidb64, token):
        password = request.data.get('password')
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        
        if user is not None and PasswordResetTokenGenerator().check_token(user, token):
            user.set_password(password)
            user.save()
            return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)
        else:
            raise ValidationError({"error": "Invalid token or user."})

class ProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        profile_data = {
            "username": user.username,
            "email": user.email,
            "image": user.image.url if user.image else None,
        }
        return Response(profile_data, status=200)

class UpdateProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        user.username = request.data.get('username', user.username)
        user.email = request.data.get('email', user.email)
        if 'image' in request.FILES:
            user.image = request.FILES['image']
        user.save()
        return Response({"message": "Profile updated successfully."})

class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        if not user.check_password(old_password):
            return Response({"error": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
