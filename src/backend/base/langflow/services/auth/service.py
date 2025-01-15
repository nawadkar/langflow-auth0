from typing import Optional
from uuid import UUID
from langflow.services.base import Service
from langflow.services.database.models.user.model import User
from langflow.services.settings.service import SettingsService

class AuthService(Service):
    name = "auth_service"

    def __init__(self, settings_service: Optional[SettingsService] = None):
        self.settings_service = settings_service
        super().__init__()

    async def verify_user(self, user_id: UUID) -> Optional[User]:
        """Verify if a user exists and is active"""
        if not user_id:
            return None
        
        async with self.session.begin() as session:
            user = await session.get(User, user_id)
            if user and user.is_active:
                return user
        return None

    def get_settings_service(self) -> SettingsService:
        if not self.settings_service:
            from langflow.services.deps import get_settings_service
            self.settings_service = get_settings_service()
        return self.settings_service
