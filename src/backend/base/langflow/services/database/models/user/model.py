from datetime import datetime
from typing import Optional, List, TYPE_CHECKING
from uuid import UUID, uuid4
from sqlmodel import Field, SQLModel, Relationship

if TYPE_CHECKING:
    from langflow.services.database.models.api_key import ApiKey

class UserBase(SQLModel):
    username: str = Field(index=True)
    email: str = Field(index=True)
    is_active: bool = Field(default=True)
    is_superuser: bool = Field(default=False)
    auth0_id: Optional[str] = Field(default=None)

class User(UserBase, table=True):
    __tablename__ = "user"
    __table_args__ = {"extend_existing": True}
    
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    password: str = Field(default="")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_login_at: Optional[datetime] = Field(default=None)
    
    # Use the original ApiKey model
    api_keys: List["ApiKey"] = Relationship(back_populates="user", sa_relationship_kwargs={"lazy": "selectin"})

class UserRead(UserBase):
    id: UUID
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime]

class UserCreate(UserBase):
    password: str

class UserUpdate(SQLModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    last_login_at: Optional[datetime] = None