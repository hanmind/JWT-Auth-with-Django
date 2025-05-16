from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserSignupSerializer, UserLoginSerializer
from .models import CustomUser
import jwt
from django.conf import settings
from django.contrib.auth import authenticate
import datetime
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated

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

# JWT 토큰 생성 함수

def create_jwt_token(user):
    payload = {
        'user_id': user.id,
        'username': user.username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iat': datetime.datetime.utcnow(),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

class LoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)
            if user is not None:
                token = create_jwt_token(user)
                return Response({"token": token}, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": {
                        "code": "INVALID_CREDENTIALS",
                        "message": "아이디 또는 비밀번호가 올바르지 않습니다."
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            "error": {
                "code": "INVALID_INPUT",
                "message": serializer.errors
            }
        }, status=status.HTTP_400_BAD_REQUEST)

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise AuthenticationFailed({
                "error": {
                    "code": "TOKEN_NOT_FOUND",
                    "message": "토큰이 없습니다."
                }
            })
        try:
            prefix, token = auth_header.split()
            if prefix.lower() != 'bearer':
                raise AuthenticationFailed({
                    "error": {
                        "code": "INVALID_TOKEN",
                        "message": "토큰이 유효하지 않습니다."
                    }
                })
        except ValueError:
            raise AuthenticationFailed({
                "error": {
                    "code": "INVALID_TOKEN",
                    "message": "토큰이 유효하지 않습니다."
                }
            })
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed({
                "error": {
                    "code": "TOKEN_EXPIRED",
                    "message": "토큰이 만료되었습니다."
                }
            })
        except jwt.InvalidTokenError:
            raise AuthenticationFailed({
                "error": {
                    "code": "INVALID_TOKEN",
                    "message": "토큰이 유효하지 않습니다."
                }
            })
        user = CustomUser.objects.filter(id=payload['user_id']).first()
        if user is None:
            raise AuthenticationFailed({
                "error": {
                    "code": "INVALID_TOKEN",
                    "message": "토큰이 유효하지 않습니다."
                }
            })
        return (user, None)

class ProtectedView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": f"Hello, {request.user.username}!"})
