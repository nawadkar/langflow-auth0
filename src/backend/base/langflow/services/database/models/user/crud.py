from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from loguru import logger
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm.attributes import flag_modified
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from langflow.services.database.models.user import User
from langflow.services.database.models.user.model import UserUpdate


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    stmt = select(User).where(User.username == username)
    return (await db.exec(stmt)).first()


async def get_user_by_id(db: AsyncSession, user_id: UUID) -> User | None:
    if isinstance(user_id, str):
        user_id = UUID(user_id)
    stmt = select(User).where(User.id == user_id)
    return (await db.exec(stmt)).first()


async def update_user(user_db: User | None, user: UserUpdate, db: AsyncSession) -> User:
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")

    # user_db_by_username = get_user_by_username(db, user.username)
    # if user_db_by_username and user_db_by_username.id != user_id:
    #     raise HTTPException(status_code=409, detail="Username already exists")

    user_data = user.model_dump(exclude_unset=True)
    changed = False
    for attr, value in user_data.items():
        if hasattr(user_db, attr) and value is not None:
            setattr(user_db, attr, value)
            changed = True

    if not changed:
        raise HTTPException(status_code=status.HTTP_304_NOT_MODIFIED, detail="Nothing to update")

    user_db.updated_at = datetime.now(timezone.utc)
    flag_modified(user_db, "updated_at")

    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=str(e)) from e

    return user_db


async def update_user_last_login_at(user_id: UUID, db: AsyncSession):
    try:
        user_data = UserUpdate(last_login_at=datetime.now(timezone.utc))
        user = await get_user_by_id(db, user_id)
        return await update_user(user, user_data, db)
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error updating user last login at: {e!s}")


async def get_or_create_user(db: AsyncSession, auth0_id: str, email: str):
    """Get or create a user with Auth0 credentials."""
    try:
        # First try to get the user
        query = select(User).where(User.auth0_id == auth0_id)
        result = await db.execute(query)
        user = result.scalar_one_or_none()
        
        if user:
            return user

        # User doesn't exist, try to create one
        try:
            # Check again in a transaction to handle race conditions
            async with db.begin():
                # Double-check the user doesn't exist
                query = select(User).where(User.auth0_id == auth0_id)
                result = await db.execute(query)
                user = result.scalar_one_or_none()
                
                if not user:
                    # Create new user
                    user = User(
                        auth0_id=auth0_id,
                        email=email,
                        username=email,  # Use email as username
                        password="",  # No password needed for Auth0
                        is_active=True,
                        is_superuser=False
                    )
                    db.add(user)
                    await db.flush()  # Ensure we can get the user ID
                    
                return user

        except IntegrityError as e:
            logger.warning(f"Race condition detected creating user {auth0_id}: {str(e)}")
            # If we hit a race condition, try one more time to get the user
            query = select(User).where(User.auth0_id == auth0_id)
            result = await db.execute(query)
            user = result.scalar_one_or_none()
            if user:
                return user
            raise  # Re-raise if we still can't find the user
            
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_or_create_user: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred while processing user"
        )
    except Exception as e:
        logger.error(f"Unexpected error in get_or_create_user: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing user"
        )
