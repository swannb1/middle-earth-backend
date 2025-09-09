from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    username: str = Field(primary_key=True)
    full_name: str
    email: str
    disabled: bool | None = None
    hashed_password: str
    token: str | None = None