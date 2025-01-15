from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
import requests
from fastapi.responses import RedirectResponse

from langflow.api.utils import DbSession
from langflow.api.v1.schemas import Token
from langflow.services.auth.utils import (
    authenticate_user,
    create_refresh_token,
    create_user_longterm_token,
    create_user_tokens,
)
from langflow.services.database.models.folder.utils import create_default_folder_if_it_doesnt_exist
from langflow.services.database.models.user.crud import get_user_by_id, get_or_create_user
from langflow.services.deps import get_settings_service, get_variable_service
from langflow.services.auth.auth0 import Auth0Service

router = APIRouter(tags=["Login"])


@router.get("/auth0/login")
async def auth0_login(request: Request):
    auth_settings = get_settings_service().auth_settings
    
    if auth_settings.AUTH_TYPE != "auth0":
        raise HTTPException(status_code=400, detail="Auth0 is not enabled")
    
    # Use the frontend URL for the callback
    base_url = "http://localhost:3000"
    redirect_uri = f"{base_url}/api/v1/auth0/callback"
    
    auth_url = (
        f"https://{auth_settings.AUTH0_DOMAIN}/authorize?"
        f"response_type=code&"
        f"client_id={auth_settings.AUTH0_CLIENT_ID}&"
        f"redirect_uri={redirect_uri}&"
        f"scope=openid%20profile%20email"
    )
    
    return {"auth_url": auth_url}


@router.post("/login", response_model=Token)
async def login_to_get_access_token(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
):
    auth_settings = get_settings_service().auth_settings
    
    # If Auth0 is enabled, redirect to Auth0 login
    if auth_settings.AUTH_TYPE == "auth0":
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/api/v1/auth0/login"},
        )
    
    try:
        user = await authenticate_user(form_data.username, form_data.password, db)
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    if user:
        tokens = await create_user_tokens(user_id=user.id, db=db, update_last_login=True)
        response.set_cookie(
            "refresh_token_lf",
            tokens["refresh_token"],
            httponly=auth_settings.REFRESH_HTTPONLY,
            samesite=auth_settings.REFRESH_SAME_SITE,
            secure=auth_settings.REFRESH_SECURE,
            expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "apikey_tkn_lflw",
            str(user.store_api_key),
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=None,  # Set to None to make it a session cookie
            domain=auth_settings.COOKIE_DOMAIN,
        )
        await get_variable_service().initialize_user_variables(user.id, db)
        # Create default folder for user if it doesn't exist
        await create_default_folder_if_it_doesnt_exist(db, user.id)
        return tokens
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.get("/auto_login")
async def auto_login(response: Response, db: DbSession):
    auth_settings = get_settings_service().auth_settings

    if auth_settings.AUTO_LOGIN:
        user_id, tokens = await create_user_longterm_token(db)
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=None,  # Set to None to make it a session cookie
            domain=auth_settings.COOKIE_DOMAIN,
        )

        user = await get_user_by_id(db, user_id)

        if user:
            if user.store_api_key is None:
                user.store_api_key = ""

            response.set_cookie(
                "apikey_tkn_lflw",
                str(user.store_api_key),  # Ensure it's a string
                httponly=auth_settings.ACCESS_HTTPONLY,
                samesite=auth_settings.ACCESS_SAME_SITE,
                secure=auth_settings.ACCESS_SECURE,
                expires=None,  # Set to None to make it a session cookie
                domain=auth_settings.COOKIE_DOMAIN,
            )

        return tokens

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "message": "Auto login is disabled. Please enable it in the settings",
            "auto_login": False,
        },
    )


@router.post("/refresh")
async def refresh_token(
    request: Request,
    response: Response,
    db: DbSession,
):
    auth_settings = get_settings_service().auth_settings

    token = request.cookies.get("refresh_token_lf")

    if token:
        tokens = await create_refresh_token(token, db)
        response.set_cookie(
            "refresh_token_lf",
            tokens["refresh_token"],
            httponly=auth_settings.REFRESH_HTTPONLY,
            samesite=auth_settings.REFRESH_SAME_SITE,
            secure=auth_settings.REFRESH_SECURE,
            expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        return tokens
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("refresh_token_lf")
    response.delete_cookie("access_token_lf")
    response.delete_cookie("apikey_tkn_lflw")
    return {"message": "Logout successful"}


@router.get("/auth0/callback")
async def auth0_callback(
    request: Request,
    response: Response,
    code: str,
    db: DbSession,
):
    auth_settings = get_settings_service().auth_settings
    
    if auth_settings.AUTH_TYPE != "auth0":
        raise HTTPException(status_code=400, detail="Auth0 is not enabled")
    
    try:
        # Exchange the code for tokens
        token_url = f"https://{auth_settings.AUTH0_DOMAIN}/oauth/token"
        token_payload = {
            "grant_type": "authorization_code",
            "client_id": auth_settings.AUTH0_CLIENT_ID,
            "client_secret": auth_settings.AUTH0_CLIENT_SECRET.get_secret_value(),
            "code": code,
            "redirect_uri": f"http://localhost:3000/api/v1/auth0/callback"
        }
        
        token_response = requests.post(token_url, json=token_payload)
        token_data = token_response.json()
        
        if 'error' in token_data:
            raise HTTPException(
                status_code=400,
                detail=f"Error exchanging code for token: {token_data['error_description']}"
            )
        
        # Get user info from userinfo endpoint
        userinfo_url = f"https://{auth_settings.AUTH0_DOMAIN}/userinfo"
        userinfo_response = requests.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {token_data['access_token']}"}
        )
        user_info = userinfo_response.json()
        
        # Create or get user from database
        user = await get_or_create_user(db, user_info['sub'], user_info.get('email', ''))
        
        # Create session tokens
        session_tokens = await create_user_tokens(user_id=user.id, db=db, update_last_login=True)
        
        # Set cookies
        response.set_cookie(
            "access_token_lf",
            session_tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        
        # Redirect to frontend after successful login
        return RedirectResponse(url="http://localhost:3000")
        
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Error during Auth0 callback: {str(e)}"
        )


@router.get("/settings/auth")
async def get_auth_settings():
    auth_settings = get_settings_service().auth_settings
    return {
        "auth_type": auth_settings.AUTH_TYPE,
        "auto_login": auth_settings.AUTO_LOGIN
    }
