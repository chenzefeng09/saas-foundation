import re, structlog, ulid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from foundation_search.domain.base import FoundationContext, foundation_context
RID=re.compile(r"^req_[0-9A-Z]{26}$"); TID=re.compile(r"^tnt_[0-9A-Z]{26}$")
PUB= frozenset({"/healthz","/readyz","/metrics","/docs","/openapi.json","/redoc"})
class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, r, call_next):
        rid=r.headers.get("X-Request-Id")
        if not rid or not RID.match(rid): rid=f"req_{ulid.new()!s}"
        r.state.request_id=rid
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=rid,path=r.url.path)
        resp=await call_next(r); resp.headers["X-Request-Id"]=rid; return resp
class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, r, call_next):
        if any(r.url.path.endswith(p) for p in PUB): return await call_next(r)
        tid=r.headers.get("X-Tenant-Id"); uid=r.headers.get("X-User-Id")
        actor=r.headers.get("X-Actor","USER"); rid=getattr(r.state,"request_id","")
        if tid and not TID.match(tid): return _p(400,"FOUNDATION.SEARCH.INPUT.INVALID_FORMAT","Invalid X-Tenant-Id",r.url.path,rid)
        t=None
        if tid:
            ctx=FoundationContext(tenant_id=tid,user_id=uid,actor=actor,request_id=rid)
            t=foundation_context.set(ctx)
        try: return await call_next(r)
        finally:
            if t is not None: foundation_context.reset(t)
def _p(s,c,d,i,rid):
    import json; from datetime import UTC, datetime
    b=json.dumps({"type":f"https://errors.foundation.example.com/{c.lower().replace('.','/')}","title":"Bad Request","status":s,"code":c,"detail":d,"instance":i,"request_id":rid,"timestamp":datetime.now(UTC).isoformat()})
    return Response(content=b,status_code=s,media_type="application/problem+json",headers={"X-Request-Id":rid})
