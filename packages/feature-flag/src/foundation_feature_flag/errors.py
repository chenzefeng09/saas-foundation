from dataclasses import dataclass; from typing import Final, Any
@dataclass(frozen=True,slots=True)
class ErrorCode: code:str; http_status:int; title:str; default_detail:str; default_user_message:str
class FoundationError(Exception):
    def __init__(self,error_code:ErrorCode,detail:str|None=None,user_message:str|None=None,extra:dict[str,Any]|None=None)->None:
        self.error_code=error_code; self.detail=detail or error_code.default_detail
        self.user_message=user_message or error_code.default_user_message; self.extra=extra or {}; super().__init__(f"{error_code.code}: {self.detail}")
TENANT_CONTEXT_MISSING:Final=ErrorCode("FOUNDATION.FEATURE_FLAG.AUTH.TENANT_CONTEXT_MISSING",401,"Tenant context missing","The request carries no tenant context (X-Tenant-Id).","缺少租户上下文。")
USER_CONTEXT_MISSING:Final=ErrorCode("FOUNDATION.FEATURE_FLAG.AUTH.USER_CONTEXT_MISSING",401,"User context missing","The request carries no user context (X-User-Id).","缺少用户身份。")
VALIDATION_FAILED:Final=ErrorCode("FOUNDATION.FEATURE_FLAG.INPUT.VALIDATION_FAILED",422,"Validation failed","Input failed semantic validation.","输入校验未通过。")
ACCESS_DENIED:Final=ErrorCode("FOUNDATION.FEATURE_FLAG.AUTHZ.ACCESS_DENIED",403,"Access denied","The caller is not allowed to perform this operation.","无权执行该操作。")
UNEXPECTED:Final=ErrorCode("FOUNDATION.FEATURE_FLAG.INTERNAL.UNEXPECTED",500,"Unexpected error","An unexpected internal error occurred.","服务异常。")
