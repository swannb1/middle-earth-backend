from pydantic import BaseModel

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class CreateUserRequest(BaseModel):
    username: str
    full_name: str
    email: str
    password: str

class TokenData(BaseModel):
    username: str | None = None