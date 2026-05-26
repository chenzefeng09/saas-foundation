from dataclasses import dataclass,field; from contextvars import ContextVar; from typing import Literal
@dataclass(frozen=True,slots=True)
class FoundationContext: tenant_id:str; user_id:str|None=None; actor:str="USER"; request_id:str=""
foundation_context:ContextVar[FoundationContext|None]=ContextVar("foundation.context",default=None)
