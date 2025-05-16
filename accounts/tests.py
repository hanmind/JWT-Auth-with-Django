from django.test import TestCase
import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from accounts.models import CustomUser

@pytest.mark.django_db
# 회원가입 API 테스트
def test_signup_success():
    client = APIClient()
    data = {"username": "pytestuser", "password": "pytestpass", "nickname": "pytestnick"}
    response = client.post("/signup", data, format="json")
    assert response.status_code == 201
    assert response.data["username"] == "pytestuser"
    assert response.data["nickname"] == "pytestnick"

# 중복 회원가입 테스트
@pytest.mark.django_db
def test_signup_duplicate():
    CustomUser.objects.create_user(username="dupuser", password="pass", nickname="dupnick")
    client = APIClient()
    data = {"username": "dupuser", "password": "pass", "nickname": "dupnick"}
    response = client.post("/signup", data, format="json")
    assert response.status_code == 400
    assert response.data["error"]["code"] == "USER_ALREADY_EXISTS"

# 로그인 성공 테스트
@pytest.mark.django_db
def test_login_success():
    CustomUser.objects.create_user(username="loginuser", password="loginpass", nickname="loginnick")
    client = APIClient()
    data = {"username": "loginuser", "password": "loginpass"}
    response = client.post("/login", data, format="json")
    assert response.status_code == 200
    assert "token" in response.data

# 로그인 실패 테스트
@pytest.mark.django_db
def test_login_fail():
    client = APIClient()
    data = {"username": "loginuser", "password": "wrongpass"}
    response = client.post("/login", data, format="json")
    assert response.status_code == 400
    assert response.data["error"]["code"] == "INVALID_CREDENTIALS"

# 토큰 보호된 API 테스트
@pytest.mark.django_db
def test_protected_success():
    user = CustomUser.objects.create_user(username="jwtuser", password="jwtpass", nickname="jwtusernick")
    client = APIClient()
    login = client.post("/login", {"username": "jwtuser", "password": "jwtpass"}, format="json")
    token = login.data["token"]
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    response = client.get("/protected")
    assert response.status_code == 200
    assert "Hello, jwtuser!" in response.data["message"]

# 토큰 없는 경우 테스트
@pytest.mark.django_db
def test_protected_no_token():
    client = APIClient()
    response = client.get("/protected")
    assert response.status_code == 401
    assert response.data["error"]["code"] == "TOKEN_NOT_FOUND"
