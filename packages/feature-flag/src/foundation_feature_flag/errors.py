from dataclasses import dataclass; from typing import Final, Any
@dataclass(frozen=True,slots=True)
class ErrorCode: code:str; http_status:int; title:str; default_detail:str; default_user_message:str
class FoundationError(Exception):
    def __init__(self,error_code:ErrorCode,detail:str|None=None,user_message:str|None=None,extra:dict[str,Any]|None=None)->None:
        self.error_code=error_code; self.detail=detail or error_code.default_detail
        self.user_message=user_message or error_code.default_user_message; self.extra=extra or {}; super().__init__(f"{error_code.code}: {self.detail}")
VALIDATION_FAILED:Final=ErrorCode("FOUNDATION.FEATURE_FLAG.INPUT.VALIDATION_FAILED",422,"Validation failed","Input failed semantic validation.","输入校验未通过。")
UNEXPECTED:Final=ErrorCode("FOUNDATION.FEATURE_FLAG.INTERNAL.UNEXPECTED",500,"Unexpected error","An unexpected internal error occurred.","服务异常。")
