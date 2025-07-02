from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from sqlalchemy import delete

from database import get_db, UserModel, ActivationTokenModel, PasswordResetTokenModel, RefreshTokenModel
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.passwords import verify_password, hash_password
from security.utils import generate_secure_token
from config import get_jwt_auth_manager, BaseAppSettings, get_settings
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()

@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(UserModel).filter(UserModel.email == data.email))
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists."
        )

    new_user = UserModel.create(email=data.email, raw_password=data.password, group_id=1)  # припустимо, group_id=1 для USER

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    token = generate_secure_token()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    activation_token = ActivationTokenModel(user_id=new_user.id, token=token, expires_at=expires_at)
    db.add(activation_token)
    await db.commit()

    print(f"Activation token for {new_user.email}: {token}")

    return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
)
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ActivationTokenModel).filter(ActivationTokenModel.token == data.token))
    token_obj = result.scalar_one_or_none()

    if not token_obj:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid activation token.")

    if token_obj.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Activation token has expired.")

    result = await db.execute(select(UserModel).filter(UserModel.id == token_obj.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    user.is_active = True
    await db.delete(token_obj)
    await db.commit()

    return MessageResponseSchema(message="User activated successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
)
async def login_user(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    result = await db.execute(select(UserModel).filter(UserModel.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    access_token_expires = timedelta(minutes=15)
    refresh_token_expires = timedelta(days=7)

    access_token = jwt_manager.create_access_token(data={"sub": str(user.id)}, expires_delta=access_token_expires)
    refresh_token = jwt_manager.create_refresh_token(data={"sub": str(user.id)}, expires_delta=refresh_token_expires)

    new_refresh_token = RefreshTokenModel.create(user_id=user.id, days_valid=7, token=refresh_token)
    db.add(new_refresh_token)
    await db.commit()

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(
    data: PasswordResetRequestSchema,
db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(UserModel).filter(UserModel.email == data.email))
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

        new_token = PasswordResetTokenModel(
            user_id=user.id,
            token=str(uuid4()),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db.add(new_token)
        await db.commit()

    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/password-reset/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(PasswordResetTokenModel).filter(PasswordResetTokenModel.token == data.token))
    token_obj = result.scalar_one_or_none()

    if not token_obj or token_obj.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired password reset token.")

    result = await db.execute(select(UserModel).filter(UserModel.id == token_obj.user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user.")

    user.password = data.new_password
    await db.delete(token_obj)
    await db.commit()

    return MessageResponseSchema(message="Password has been reset successfully.")


@router.post("/token/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    user_id = jwt_manager.verify_refresh_token(data.refresh_token)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")

    result = await db.execute(select(RefreshTokenModel).filter(RefreshTokenModel.token == data.refresh_token))
    token_entry = result.scalar_one_or_none()

    if not token_entry:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found or expired.")

    new_access_token = jwt_manager.create_access_token(data={"sub": str(user_id)})
    new_refresh_token = jwt_manager.create_refresh_token(data={"sub": str(user_id)})

    await db.delete(token_entry)
    new_refresh_token_obj = RefreshTokenModel.create(user_id=user_id, days_valid=7, token=new_refresh_token)
    db.add(new_refresh_token_obj)
    await db.commit()

    return TokenRefreshResponseSchema(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer"
    )