# from datetime import datetime
# from typing import Optional
# from uuid import UUID, uuid4
# from sqlmodel import Field, SQLModel, Relationship
# from langflow.services.database.models.user.model import User

# class ApiKeyBase(SQLModel):
#     name: str = Field(index=True)
#     key: str = Field(index=True)
#     is_active: bool = Field(default=True)

# class ApiKey(ApiKeyBase, table=True):
#     __tablename__ = "apikey"
#     __table_args__ = {"extend_existing": True}
    
#     id: UUID = Field(default_factory=uuid4, primary_key=True)
#     created_at: datetime = Field(default_factory=datetime.utcnow)
#     last_used_at: Optional[datetime] = Field(default=None)
#     user_id: UUID = Field(foreign_key="user.id")
#     user: User = Relationship(back_populates="api_keys", sa_relationship_kwargs={"lazy": "selectin"})

# class ApiKeyCreate(ApiKeyBase):
#     pass

# class ApiKeyRead(ApiKeyBase):
#     id: UUID
#     created_at: datetime
#     last_used_at: Optional[datetime]
#     user_id: UUID

# class UnmaskedApiKeyRead(ApiKeyRead):
#     key: str