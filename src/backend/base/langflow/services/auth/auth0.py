from typing import Dict
import jwt
import requests
from fastapi import HTTPException, status
import json
from jwt.algorithms import RSAAlgorithm

class Auth0Service:
    def __init__(self, settings):
        self.domain = settings.AUTH0_DOMAIN
        self.client_id = settings.AUTH0_CLIENT_ID
        self.client_secret = settings.AUTH0_CLIENT_SECRET.get_secret_value()
        self.audience = settings.AUTH0_AUDIENCE
        self._jwks = None

    @property
    def jwks(self):
        if self._jwks is None:
            jwks_url = f'https://{self.domain}/.well-known/jwks.json'
            self._jwks = requests.get(jwks_url).json()
        return self._jwks

    def get_key(self, kid):
        for key in self.jwks['keys']:
            if key['kid'] == kid:
                return RSAAlgorithm.from_jwk(json.dumps(key))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unable to find appropriate key",
        )

    async def verify_token(self, token: str) -> Dict:
        try:
            # Decode without verification first to get the kid
            unverified_header = jwt.get_unverified_header(token)
            
            # Get the key for this token
            key = self.get_key(unverified_header['kid'])
            
            # Now verify the token with the correct key
            payload = jwt.decode(
                token,
                key=key,
                algorithms=['RS256'],
                audience=self.client_id,  # Changed from self.audience
                issuer=f'https://{self.domain}/'
            )
            return payload
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTClaimsError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid claims. Please check the audience and issuer."
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid authentication credentials: {str(e)}"
            ) 