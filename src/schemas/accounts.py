from pydantic import BaseModel, EmailStr, Field, constr, validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)

    @validator("password")
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        return v

class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

class UserActivationRequestSchema(BaseModel):
    token: str

class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str

class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str

class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str

class MessageResponseSchema(BaseModel):
    message: str

class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

class PasswordResetCompleteRequestSchema(BaseModel):
    token: constr(min_length=36, max_length=36)  # UUID string length
    new_password: constr(min_length=8)
