from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class Category(str, Enum):
    INJECTION = "INJECTION"
    AUTH = "AUTH"
    CRYPTO = "CRYPTO"
    SECRET = "SECRET"
    DESERIALIZATION = "DESERIALIZATION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    OTHER = "OTHER"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


Source = Literal["llm", "semgrep"]


class Finding(BaseModel):
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    category: Category
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    code_snippet: str
    source: Source

    @model_validator(mode="after")
    def _check_line_range(self) -> "Finding":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        return self
