from pydantic import BaseModel, Field, HttpUrl


class SourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    url: HttpUrl
    category: str = Field(default="cyber", min_length=2, max_length=50)
    enabled: bool = True


class SourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    category: str | None = Field(default=None, min_length=2, max_length=50)
    enabled: bool | None = None
