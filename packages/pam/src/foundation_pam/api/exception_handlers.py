from datetime import UTC,datetime; from typing import Any
from fastapi import FastAPI,Request; from fastapi.exceptions import RequestValidationError; from fastapi.responses import JSONResponse
from foundation_pam.errors import UNEXPECTED,VALIDATION_FAILED,FoundationError
from foundation_pam.observability import get_logger
log=get_logger(__name__); _B="https://errors.foundation.example.com"
def _body(*,code,title,status,detail,instance,request_id,user_message=None,extra=None):
    out={"type":f"{_B}/{code.lower().replace('.','/')}","title":title,"status":status,"code":code,"detail":detail,"instance":instance,"request_id":request_id,"timestamp":datetime.now(UTC).isoformat()}
    if user_message: out["user_message"]=user_message
    if extra: out.update(extra)
    return out
def install_exception_handlers(app:FastAPI):
    @app.exception_handler(FoundationError)
    async def _fe(r:Request,exc:FoundationError):
        ec=exc.error_code; return JSONResponse(status_code=ec.http_status,media_type="application/problem+json",content=_body(code=ec.code,title=ec.title,status=ec.http_status,detail=exc.detail,instance=r.url.path,request_id=getattr(r.state,"request_id",""),user_message=exc.user_message,extra=exc.extra))
    @app.exception_handler(RequestValidationError)
    async def _ve(r:Request,exc:RequestValidationError):
        ec=VALIDATION_FAILED; errors=[{"field":"/" + "/".join(str(p) for p in e["loc"][1:]),"code":e["type"].upper().replace(".","_"),"detail":e["msg"]} for e in exc.errors()]
        return JSONResponse(status_code=ec.http_status,media_type="application/problem+json",content=_body(code=ec.code,title=ec.title,status=ec.http_status,detail=f"Validation failed for {len(errors)} field(s)",instance=r.url.path,request_id=getattr(r.state,"request_id",""),extra={"errors":errors}))
    @app.exception_handler(Exception)
    async def _ue(r:Request,exc:Exception):
        log.exception("unhandled.error",path=r.url.path,error=str(exc)); ec=UNEXPECTED
        return JSONResponse(status_code=ec.http_status,media_type="application/problem+json",content=_body(code=ec.code,title=ec.title,status=ec.http_status,detail=ec.default_detail,instance=r.url.path,request_id=getattr(r.state,"request_id",""),user_message=ec.default_user_message))
