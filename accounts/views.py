from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserSignupSerializer
from .models import CustomUser

# Create your views here.

class SignupView(APIView):
    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            nickname = serializer.validated_data['nickname']
            if CustomUser.objects.filter(username=username).exists():
                return Response({
                    "error": {
                        "code": "USER_ALREADY_EXISTS",
                        "message": "이미 가입된 사용자입니다."
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            if CustomUser.objects.filter(nickname=nickname).exists():
                return Response({
                    "error": {
                        "code": "USER_ALREADY_EXISTS",
                        "message": "이미 가입된 사용자입니다."
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            user = serializer.save()
            return Response({
                "username": user.username,
                "nickname": user.nickname
            }, status=status.HTTP_201_CREATED)
        return Response({
            "error": {
                "code": "INVALID_INPUT",
                "message": serializer.errors
            }
        }, status=status.HTTP_400_BAD_REQUEST)
