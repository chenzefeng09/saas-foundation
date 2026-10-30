from dataclasses import dataclass; from typing import Final, Any
@dataclass(frozen=True,slots=True)
class ErrorCode: code:str; http_status:int; title:str; default_detail:str; default_user_message:str
class FoundationError(Exception):
    def __init__(self,error_code:ErrorCode,detail:str|None=None,user_message:str|None=None,extra:dict[str,Any]|None=None)->None:
        self.error_code=error_code; self.detail=detail or error_code.default_detail
        self.user_message=user_message or error_code.default_user_message; self.extra=extra or {}; super().__init__(f"{error_code.code}: {self.detail}")
TENANT_CONTEXT_MISSING:Final=ErrorCode("FOUNDATION.LLM_GATEWAY.AUTH.TENANT_CONTEXT_MISSING",401,"Tenant context missing","The request carries no tenant context (X-Tenant-Id).","缺少租户上下文。")
VALIDATION_FAILED:Final=ErrorCode("FOUNDATION.LLM_GATEWAY.INPUT.VALIDATION_FAILED",422,"Validation failed","Input failed semantic validation.","输入校验未通过。")
UNEXPECTED:Final=ErrorCode("FOUNDATION.LLM_GATEWAY.INTERNAL.UNEXPECTED",500,"Unexpected error","An unexpected internal error occurred.","服务异常。")
# P1 enterprise gateway error codes
QUOTA_EXCEEDED:Final=ErrorCode("FOUNDATION.LLM_GATEWAY.QUOTA.EXCEEDED",402,"Quota exceeded","LLM token quota exceeded for this tenant.","LLM token 配额已用尽，请联系管理员升级计划。")
VIRTUAL_KEY_MISMATCH:Final=ErrorCode("FOUNDATION.LLM_GATEWAY.AUTH.VIRTUAL_KEY_MISMATCH",403,"Virtual key mismatch","The virtual key does not belong to the authenticated tenant.","虚拟 Key 与租户不匹配。")
VIRTUAL_KEY_REQUIRED:Final=ErrorCode("FOUNDATION.LLM_GATEWAY.AUTH.VIRTUAL_KEY_REQUIRED",401,"Virtual key required","X-LLM-Virtual-Key is required for LLM gateway requests.","缺少 LLM 虚拟 Key。")
PERMISSION_DENIED:Final=ErrorCode("FOUNDATION.LLM_GATEWAY.AUTH.PERMISSION_DENIED",403,"Permission denied","The actor is not allowed to perform this operation.","当前身份无权执行该操作。")
PROVIDER_NOT_FOUND:Final=ErrorCode("FOUNDATION.LLM_GATEWAY.PROVIDER.NOT_FOUND",404,"Provider not found","No enabled provider found for this model/tenant.","未找到匹配的 LLM Provider。")
PROVIDER_UPSTREAM_ERROR:Final=ErrorCode("FOUNDATION.LLM_GATEWAY.PROVIDER.UPSTREAM_ERROR",502,"Provider upstream error","The upstream LLM provider returned an error.","上游 LLM 服务异常。")
