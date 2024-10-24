from pydantic import BaseModel,EmailStr
from typing import Optional

class RegisterUserSchema(BaseModel):
    username: str
    email:EmailStr
    password: str


class GetAllUserSchema(BaseModel):
    id: str
    username: str
    email:str
    password: str
    is_active: bool
    is_verified: bool
    is_deleted: bool
    created_at: str
    modified_at: str

class UpdateUserSchema(BaseModel):
    username: Optional[str] = None
    email:Optional[EmailStr] = None
    password: Optional[str] = None
  