import hmac, re, structlog, ulid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from foundation_llm_gateway.config import get_settings
from foundation_llm_gateway.domain.base import FoundationContext, foundation_context
from foundation_llm_gateway.observability import get_logger
log=get_logger(__name__)
RID=re.compile(r"^req_[0-9A-Z]{26}$"); TID=re.compile(r"^tnt_[0-9A-Z]{26}$")
PUB= frozenset({"/healthz","/readyz","/metrics","/docs","/openapi.json","/redoc"})
# authz's X-Internal-Admin-Token scheme, for SERVICE: platform-internal callers
# prove themselves with the pre-shared LLM_GATEWAY_INTERNAL_SERVICE_TOKEN.
SERVICE_TOKEN_HEADER="X-Internal-Service-Token"
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
        # SERVICE is the one actor that is verified, not taken from the header:
        # an unproven claim is treated as USER, the same silent downgrade authz
        # applies to ADMIN.
        if actor=="SERVICE" and not _service_token_ok(r):
            log.warning("service_actor.unverified",token_presented=SERVICE_TOKEN_HEADER in r.headers)
            actor="USER"
        if tid and not TID.match(tid): return _p(400,"FOUNDATION.LLM_GATEWAY.INPUT.INVALID_FORMAT","Invalid X-Tenant-Id",r.url.path,rid)
        t=None
        if tid:
            ctx=FoundationContext(tenant_id=tid,user_id=uid,actor=actor,request_id=rid)
            t=foundation_context.set(ctx)
        try: return await call_next(r)
        finally:
            if t is not None: foundation_context.reset(t)
def _service_token_ok(r)->bool:
    presented=r.headers.get(SERVICE_TOKEN_HEADER,"")
    configured=get_settings().internal_service_token.get_secret_value()
    # An empty configured token disables SERVICE altogether. Constant-time
    # compare, on bytes: compare_digest raises on a non-ASCII str.
    return bool(presented and configured) and hmac.compare_digest(presented.encode(),configured.encode())
def _p(s,c,d,i,rid):
    import json; from datetime import UTC, datetime
    b=json.dumps({"type":f"https://errors.foundation.example.com/{c.lower().replace('.','/')}","title":"Bad Request","status":s,"code":c,"detail":d,"instance":i,"request_id":rid,"timestamp":datetime.now(UTC).isoformat()})
    return Response(content=b,status_code=s,media_type="application/problem+json",headers={"X-Request-Id":rid})
