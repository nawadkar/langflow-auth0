import pytest
from unittest.mock import patch, MagicMock
from langflow.services.auth.utils import get_password_hash
from langflow.services.database.models.user import User
from langflow.services.deps import session_scope, get_settings_service
from sqlalchemy.exc import IntegrityError
import requests


@pytest.fixture
def test_user():
    return User(
        username="testuser",
        password=get_password_hash("testpassword"),  # Assuming password needs to be hashed
        is_active=True,
        is_superuser=False,
    )


async def test_login_successful(client, test_user):
    # Adding the test user to the database
    try:
        async with session_scope() as session:
            session.add(test_user)
            await session.commit()
    except IntegrityError:
        pass

    response = await client.post("api/v1/login", data={"username": "testuser", "password": "testpassword"})
    assert response.status_code == 200
    assert "access_token" in response.json()


async def test_login_unsuccessful_wrong_username(client):
    response = await client.post("api/v1/login", data={"username": "wrongusername", "password": "testpassword"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


async def test_login_unsuccessful_wrong_password(client, test_user, async_session):
    # Adding the test user to the database
    async_session.add(test_user)
    await async_session.commit()

    response = await client.post("api/v1/login", data={"username": "testuser", "password": "wrongpassword"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


@pytest.fixture
def mock_auth0_settings(monkeypatch):
    settings = get_settings_service().auth_settings
    settings.AUTH_TYPE = "auth0"
    settings.AUTH0_DOMAIN = "test.auth0.com"
    settings.AUTH0_CLIENT_ID = "test-client-id"
    settings.AUTH0_CLIENT_SECRET = "test-client-secret"
    return settings


async def test_auth0_callback_successful(client, async_session, mock_auth0_settings):
    # Mock successful token exchange
    mock_token_response = MagicMock()
    mock_token_response.json.return_value = {
        "access_token": "test-token",
        "id_token": "test-id-token"
    }
    mock_token_response.raise_for_status.return_value = None
    
    # Mock successful userinfo fetch
    mock_userinfo_response = MagicMock()
    mock_userinfo_response.json.return_value = {
        "sub": "auth0|123",
        "email": "test@example.com"
    }
    mock_userinfo_response.raise_for_status.return_value = None
    
    with patch("requests.post", return_value=mock_token_response), \
         patch("requests.get", return_value=mock_userinfo_response):
        
        response = await client.get("/api/v1/auth0/callback?code=test-code")
        assert response.status_code == 307  # Redirect
        assert response.headers["location"] == "http://localhost:3000"


async def test_auth0_callback_token_error(client, async_session, mock_auth0_settings):
    # Mock failed token exchange
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = requests.RequestException("Token error")
    
    with patch("requests.post", return_value=mock_response):
        response = await client.get("/api/v1/auth0/callback?code=test-code")
        assert response.status_code == 502
        assert "Error communicating with Auth0 service" in response.json()["detail"]


async def test_auth0_callback_userinfo_error(client, async_session, mock_auth0_settings):
    # Mock successful token exchange but failed userinfo
    mock_token_response = MagicMock()
    mock_token_response.json.return_value = {"access_token": "test-token"}
    mock_token_response.raise_for_status.return_value = None
    
    mock_userinfo_response = MagicMock()
    mock_userinfo_response.raise_for_status.side_effect = requests.RequestException("Userinfo error")
    
    with patch("requests.post", return_value=mock_token_response), \
         patch("requests.get", return_value=mock_userinfo_response):
        
        response = await client.get("/api/v1/auth0/callback?code=test-code")
        assert response.status_code == 502
        assert "Error fetching user information from Auth0" in response.json()["detail"]


async def test_auth0_callback_db_error(client, async_session, mock_auth0_settings):
    # Mock successful auth0 responses but DB error
    mock_token_response = MagicMock()
    mock_token_response.json.return_value = {"access_token": "test-token"}
    mock_token_response.raise_for_status.return_value = None
    
    mock_userinfo_response = MagicMock()
    mock_userinfo_response.json.return_value = {
        "sub": "auth0|123",
        "email": "test@example.com"
    }
    mock_userinfo_response.raise_for_status.return_value = None
    
    with patch("requests.post", return_value=mock_token_response), \
         patch("requests.get", return_value=mock_userinfo_response), \
         patch("langflow.services.database.models.user.crud.get_or_create_user", 
               side_effect=IntegrityError("statement", "params", "orig")):
        
        response = await client.get("/api/v1/auth0/callback?code=test-code")
        assert response.status_code == 500
        assert "Error processing user data" in response.json()["detail"]
