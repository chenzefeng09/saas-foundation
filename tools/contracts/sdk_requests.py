"""Check the SDKs' golden requests against a service and its OpenAPI contract.

``contracts/sdk/<service>.json`` pins the exact HTTP request every hand-written
SDK method sends (see ``contracts/sdk/README.md``). The Python and TypeScript
SDK suites assert that their methods send exactly those requests; each service
suite calls into this module to assert, from the other side, that

* every request reaches a route of the live FastAPI app that accepts it
  (``app_problems``), and
* ``contracts/openapi/<service>.yaml`` documents that request and declares the
  same parameters and body fields as the route (``contract_problems``).

FastAPI ignores query parameters a route does not declare and pydantic drops
body keys a model does not declare, so a misspelt name still gets a 2xx and
silently does something else. Every check here therefore reports undeclared
names, not only missing required ones.

It needs only FastAPI and PyYAML, so any service's test environment can run it
(PyYAML comes with ``uvicorn[standard]``, which every service depends on).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from fastapi import FastAPI
from fastapi.dependencies.utils import get_flat_dependant, request_params_to_args
from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.datastructures import QueryParams
from starlette.routing import Match

ROOT = Path(__file__).resolve().parents[2]
# What both SDK transports put on every request (sdks/*/..._transport / transport.ts).
SDK_HEADERS = frozenset(
    {
        "authorization",
        "x-tenant-id",
        "x-request-id",
        "x-user-id",
        "accept",
        "user-agent",
        "content-type",
        "accept-language",
    }
)
_HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
_MISSING = object()


@dataclass(frozen=True)
class Case:
    """One golden request: what one SDK method call puts on the wire."""

    id: str
    method: str
    path: str
    query: dict[str, list[str]]
    body: Any = _MISSING

    @property
    def has_body(self) -> bool:
        return self.body is not _MISSING

    def __str__(self) -> str:
        return self.id


def load_cases(service: str) -> list[Case]:
    doc = json.loads((ROOT / "contracts" / "sdk" / f"{service}.json").read_text())
    cases = []
    for raw in doc["cases"]:
        req = raw["request"]
        query = {
            k: [str(x) for x in v] if isinstance(v, list) else [str(v)]
            for k, v in (req.get("query") or {}).items()
        }
        cases.append(Case(raw["id"], req["method"], req["path"], query, req.get("json", _MISSING)))
    return cases


# --------------------------------------------------------------------------- app


def app_problems(app: FastAPI, case: Case) -> list[str]:
    """Why the live app would reject ``case`` or silently drop part of it."""
    route, path_params, problem = _match_route(app.router.routes, _scope(case))
    if route is None:
        return [problem]
    flat = get_flat_dependant(route.dependant, skip_repeats=True)
    _, errors = request_params_to_args(flat.path_params, path_params)
    problems = _pydantic_errors(errors)
    query = QueryParams([(k, v) for k, values in case.query.items() for v in values])
    _, errors = request_params_to_args(flat.query_params, query)
    problems += _pydantic_errors(errors)
    declared = _declared_query(flat.query_params)
    problems += [
        f"query.{name}: not a parameter of {case.method} {route.path} (FastAPI ignores it)"
        for name in case.query
        if name not in declared
    ]
    problems += [
        f"header.{name}: required, and the SDK transports never send it"
        for name in (_header_name(f) for f in flat.header_params if f.required)
        if name not in SDK_HEADERS
    ]

    body_field = route.body_field
    if body_field is None:
        if case.has_body:
            problems.append(f"sends a JSON body, but {case.method} {route.path} reads none")
    elif not case.has_body:
        if body_field.required:
            problems.append(f"{case.method} {route.path} requires a JSON body; none sent")
    else:
        _, errors = body_field.validate(case.body, {}, loc=("body",))
        problems += _pydantic_errors(errors or [])
        spec = _Spec.from_dict(app.openapi())
        op = spec.doc["paths"].get(route.path_format, {}).get(case.method.lower())
        if op is None:
            problems.append(f"{case.method} {route.path} is left out of the app's OpenAPI")
        else:
            schema = _json_schema(spec, op.get("requestBody"), None)
            problems += _walk(case.body, schema, spec, None, "body", check_values=False)
    return problems


def _header_name(field: Any) -> str:
    name = field.alias
    if getattr(field.field_info, "convert_underscores", True):
        name = name.replace("_", "-")
    return name.lower()


def _scope(case: Case) -> dict[str, Any]:
    return {"type": "http", "method": case.method, "path": case.path, "root_path": ""}


def _match_route(
    routes: list[Any], scope: dict[str, Any]
) -> tuple[APIRoute | None, dict[str, Any], str]:
    """First FULL match in declaration order, exactly like Starlette's router."""
    allowed: list[str] = []
    for route in routes:
        match, child = route.matches(scope)
        if match is Match.FULL:
            if isinstance(route, APIRoute):
                return route, child.get("path_params", {}), ""
            if hasattr(route, "routes"):
                found = _match_route(route.routes, {**scope, **child})
                if found[0] is not None:
                    return found
            return (
                None,
                {},
                f"{scope['method']} {scope['path']} reaches {route!r}, not an API route",
            )
        if match is Match.PARTIAL:
            allowed += sorted(getattr(route, "methods", None) or ())
    if allowed:
        return None, {}, f"405: {scope['method']} not allowed on {scope['path']} (has {allowed})"
    return None, {}, f"404: no route for {scope['method']} {scope['path']}"


def _declared_query(fields: list[Any]) -> set[str]:
    if len(fields) == 1 and _is_model(fields[0].type_):
        return {f.alias or n for n, f in fields[0].type_.model_fields.items()}
    return {f.alias for f in fields}


def _is_model(tp: Any) -> bool:
    return isinstance(tp, type) and issubclass(tp, BaseModel)


def _pydantic_errors(errors: list[Any]) -> list[str]:
    return [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in errors]


# ---------------------------------------------------------------------- contract


def contract_problems(service: str, app: FastAPI, case: Case) -> list[str]:
    """Why ``contracts/openapi/<service>.yaml`` disagrees with ``case`` or its route."""
    spec = load_contract(service)
    found = spec.find(case.method, case.path)
    if isinstance(found, str):
        return [found]
    op, base, path_params = found
    problems = []
    params = spec.parameters(op, base)
    for name, value in path_params.items():
        param = params.get(("path", name))
        if param is None:
            problems.append(f"path.{name}: not declared")
        else:
            problems += _walk_param([value], param, spec, base, f"path.{name}")
    for (where, name), param in params.items():
        if where == "query" and name in case.query:
            problems += _walk_param(case.query[name], param, spec, base, f"query.{name}")
        elif where == "query" and param.get("required"):
            problems.append(f"query.{name}: required but not sent")
    problems += [
        f"query.{name}: not declared" for name in case.query if ("query", name) not in params
    ]
    body = op.get("requestBody")
    if body is None:
        if case.has_body:
            problems.append("sends a JSON body, but the operation declares none")
    elif not case.has_body:
        if spec.deref(body, base)[0].get("required"):
            problems.append("the operation requires a JSON body; none sent")
    else:
        problems += _walk(case.body, _json_schema(spec, body, base), spec, base, "body")
    if not problems:
        problems += _shape_problems(app, case, spec, op, base)
    return problems


def _shape_problems(
    app: FastAPI, case: Case, spec: _Spec, op: dict, base: Path | None
) -> list[str]:
    """The contract operation must declare the same inputs as the route it documents."""
    route, _, problem = _match_route(app.router.routes, _scope(case))
    if route is None:
        return [problem]
    live = _Spec.from_dict(app.openapi())
    live_op = live.doc["paths"][route.path_format][case.method.lower()]
    problems = []
    want = _query_shape(live, live_op, None)
    have = _query_shape(spec, op, base)
    for name in sorted(want.keys() | have.keys()):
        if name not in have:
            problems.append(f"query.{name}: the route declares it, the contract does not")
        elif name not in want:
            problems.append(f"query.{name}: the contract declares it, the route does not")
        elif want[name] != have[name]:
            problems.append(f"query.{name}: required={want[name]} in the route, {have[name]} here")
    want_body, route_maps = _body_shape(live, live_op.get("requestBody"), None)
    have_body, _ = _body_shape(spec, op.get("requestBody"), base)
    for name in sorted(want_body.keys() | have_body.keys()):
        if name not in have_body:
            problems.append(f"{name}: the route declares it, the contract does not")
        elif name not in want_body:
            # under a free-form map of the route any key goes; the contract may name them
            if not any(name.startswith(f"{at}.") for at in route_maps):
                problems.append(f"{name}: the contract declares it, the route does not")
        elif want_body[name] != have_body[name]:
            problems.append(
                f"{name}: required={want_body[name]} in the route, {have_body[name]} here"
            )
    return problems


def _query_shape(spec: _Spec, op: dict, base: Path | None) -> dict[str, bool]:
    return {
        name: bool(p.get("required"))
        for (where, name), p in spec.parameters(op, base).items()
        if where == "query"
    }


def _body_shape(
    spec: _Spec, body: dict | None, base: Path | None
) -> tuple[dict[str, bool], set[str]]:
    """``{"body": required, "body.<field>": required, ...}`` down through nested objects,
    plus where the body is a free-form map (``dict[str, X]``) that takes any key."""
    if body is None:
        return {}, set()
    shape = {"body": bool(spec.deref(body, base)[0].get("required"))}
    maps: set[str] = set()
    _fields(spec, *_json_schema_at(spec, body, base), "body", shape, maps, depth=0)
    return shape, maps


def _fields(
    spec: _Spec,
    schema: Any,
    base: Path | None,
    at: str,
    shape: dict[str, bool],
    maps: set[str],
    depth: int,
) -> None:
    schema, base = spec.merged(schema, base)
    alts = [
        a for a in schema.get("anyOf") or schema.get("oneOf") or [] if not _is_null(spec, a, base)
    ]
    if len(alts) == 1:
        _fields(spec, alts[0], base, at, shape, maps, depth)
        return
    if schema.get("type") == "array" and "items" in schema:
        _fields(spec, schema["items"], base, f"{at}[]", shape, maps, depth)
        return
    if depth >= 4:
        return
    if "properties" not in schema and schema.get("type") in (None, "object"):
        if schema.get("additionalProperties", True) is not False:
            maps.add(at)
        return
    required = set(schema.get("required") or ())
    for name, sub in (schema.get("properties") or {}).items():
        shape[f"{at}.{name}"] = name in required
        _fields(spec, sub, base, f"{at}.{name}", shape, maps, depth + 1)


def _is_null(spec: _Spec, schema: Any, base: Path | None) -> bool:
    return spec.deref(schema, base)[0].get("type") == "null"


# ------------------------------------------------------------------- spec model


_CONTRACTS: dict[str, _Spec] = {}


def load_contract(service: str) -> _Spec:
    if service not in _CONTRACTS:
        _CONTRACTS[service] = _Spec.from_file(ROOT / "contracts" / "openapi" / f"{service}.yaml")
    return _CONTRACTS[service]


class _Spec:
    """An OpenAPI document plus whatever files its ``$ref``s point into."""

    def __init__(self, doc: dict, path: Path | None) -> None:
        self.doc, self.path = doc, path
        self._files: dict[Path, Any] = {}
        prefix = urlparse((doc.get("servers") or [{"url": ""}])[0]["url"]).path.rstrip("/")
        self._ops = []
        for template, item in (doc.get("paths") or {}).items():
            names, pattern, pos = [], "^" + re.escape(prefix), 0
            for m in re.finditer(r"\{([^}]+)\}", template):
                pattern += re.escape(template[pos : m.start()]) + f"(?P<p{len(names)}>[^/]+)"
                names.append(m.group(1))
                pos = m.end()
            regex = re.compile(pattern + re.escape(template[pos:]) + "$")
            literal = len(re.sub(r"\{[^}]+\}", "", template))
            self._ops.append((regex, names, literal, item))

    @classmethod
    def from_file(cls, path: Path) -> _Spec:
        return cls(yaml.safe_load(path.read_text()), path)

    @classmethod
    def from_dict(cls, doc: dict) -> _Spec:
        return cls(doc, None)

    def find(self, method: str, path: str) -> tuple[dict, Path | None, dict[str, str]] | str:
        hits = sorted(
            (
                (dict(zip(names, m.groups(), strict=True)), literal, item)
                for regex, names, literal, item in self._ops
                if (m := regex.match(path))
            ),
            key=lambda hit: -hit[1],
        )
        allowed = sorted({k.upper() for _, _, item in hits for k in item if k in _HTTP_METHODS})
        for path_params, _, item in hits:
            if method.lower() in item:
                op = dict(item[method.lower()])
                op["parameters"] = [*(item.get("parameters") or []), *(op.get("parameters") or [])]
                return op, self.path, path_params
        if allowed:
            return f"405: the contract has no {method} {path} (has {allowed})"
        return f"404: the contract has no {method} {path}"

    def parameters(self, op: dict, base: Path | None) -> dict[tuple[str, str], dict]:
        params = {}
        for raw in op.get("parameters") or []:
            param, _ = self.deref(raw, base)
            params[(param["in"], param["name"])] = param
        return params

    def deref(self, node: Any, base: Path | None) -> tuple[Any, Path | None]:
        seen = 0
        while isinstance(node, dict) and "$ref" in node:
            file, _, pointer = node["$ref"].partition("#")
            if file:
                base = (base.parent / file).resolve() if base else Path(file)
            target = self._load(base)
            for part in pointer.strip("/").split("/") if pointer.strip("/") else []:
                target = target[part.replace("~1", "/").replace("~0", "~")]
            node, seen = target, seen + 1
            if seen > 50:
                raise ValueError(f"$ref loop at {pointer}")
        return node, base

    def merged(self, node: Any, base: Path | None) -> tuple[dict, Path | None]:
        """``node`` with ``$ref``s followed and ``allOf`` parts folded into one schema."""
        node, base = self.deref(node, base)
        if not isinstance(node, dict) or "allOf" not in node:
            return node if isinstance(node, dict) else {}, base
        out: dict[str, Any] = {k: v for k, v in node.items() if k != "allOf"}
        props, required = dict(out.get("properties") or {}), list(out.get("required") or [])
        for part in node["allOf"]:
            sub, sub_base = self.merged(part, base)
            for name, schema in (sub.get("properties") or {}).items():
                props.setdefault(name, _rebased(schema, sub_base, base))
            required += sub.get("required") or []
            for key, value in sub.items():
                if key not in ("properties", "required"):
                    out.setdefault(key, value)
        if props:
            out["properties"] = props
        if required:
            out["required"] = sorted(set(required))
        return out, base

    def _load(self, path: Path | None) -> Any:
        if path is None or path == self.path:
            return self.doc
        if path not in self._files:
            self._files[path] = yaml.safe_load(path.read_text())
        return self._files[path]


def _rebased(schema: Any, schema_base: Path | None, base: Path | None) -> Any:
    """Keep a relative ``$ref`` valid after moving ``schema`` from one file into another."""
    if schema_base == base or not isinstance(schema, dict) or "$ref" not in schema:
        return schema
    file, _, pointer = schema["$ref"].partition("#")
    target = (schema_base.parent / file).resolve() if file and schema_base else schema_base
    return {**schema, "$ref": f"{target}#{pointer}"}


def _json_schema(spec: _Spec, body: dict | None, base: Path | None) -> Any:
    return _json_schema_at(spec, body, base)[0]


def _json_schema_at(spec: _Spec, body: dict | None, base: Path | None) -> tuple[Any, Path | None]:
    if body is None:
        return {}, base
    body, base = spec.deref(body, base)
    content = body.get("content") or {}
    media = content.get("application/json") or next(iter(content.values()), {})
    return media.get("schema") or {}, base


# -------------------------------------------------------------------- validator


_JSON_TYPES = {
    type(None): {"null"},
    bool: {"boolean"},
    int: {"integer", "number"},
    float: {"number"},
    str: {"string"},
    list: {"array"},
    dict: {"object"},
}


def _types(schema: dict) -> set[str] | None:
    declared = schema.get("type")
    if declared is None:
        return {"object"} if "properties" in schema else None
    types = {declared} if isinstance(declared, str) else set(declared)
    if schema.get("nullable"):
        types.add("null")
    return types


def _walk(
    value: Any, schema: Any, spec: _Spec, base: Path | None, at: str, *, check_values: bool = True
) -> list[str]:
    """Problems with ``value`` under ``schema``.

    ``check_values=False`` reports only undeclared object keys: the app side
    leaves value checks to pydantic, which is what the service really runs.
    """
    schema, base = spec.merged(schema, base)
    if not schema:
        return []
    types = _types(schema)
    fits = types is None or bool(_JSON_TYPES[type(value)] & types)
    alts = schema.get("anyOf") or schema.get("oneOf")
    if alts:
        results = []
        for alt in alts:
            alt_schema, alt_base = spec.merged(alt, base)
            alt_types = _types(alt_schema)
            if (
                not check_values
                and alt_types is not None
                and not _JSON_TYPES[type(value)] & alt_types
            ):
                continue
            results.append(_walk(value, alt_schema, spec, alt_base, at, check_values=check_values))
            if not results[-1]:
                break
        if results and all(results):
            return min(results, key=len)
        if check_values and not results:
            return [f"{at}: {value!r} matches none of its alternatives"]
    if check_values:
        if not fits:
            return [f"{at}: {value!r} is not of type {sorted(types or ())}"]
        problems = _value_problems(value, schema, at)
        if problems:
            return problems
    elif not fits:
        return []
    problems = []
    if isinstance(value, dict):
        props = schema.get("properties")
        extra = schema.get("additionalProperties")
        if check_values:
            problems += [
                f"{at}.{name}: required but not sent"
                for name in schema.get("required") or ()
                if name not in value
            ]
        for key, item in value.items():
            if props is not None and key in props:
                problems += _walk(
                    item, props[key], spec, base, f"{at}.{key}", check_values=check_values
                )
            elif isinstance(extra, dict):
                problems += _walk(item, extra, spec, base, f"{at}.{key}", check_values=check_values)
            elif props is not None and not extra:
                problems.append(f"{at}.{key}: not a declared field (it would be dropped)")
    elif isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            problems += _walk(
                item, schema["items"], spec, base, f"{at}[{i}]", check_values=check_values
            )
    return problems


def _value_problems(value: Any, schema: dict, at: str) -> list[str]:
    if "enum" in schema and value not in schema["enum"]:
        return [f"{at}: {value!r} is not one of {schema['enum']}"]
    if "const" in schema and value != schema["const"]:
        return [f"{at}: {value!r} is not {schema['const']!r}"]
    checks = []
    if isinstance(value, str):
        checks = [
            ("minLength", lambda n: len(value) >= n),
            ("maxLength", lambda n: len(value) <= n),
            ("pattern", lambda p: re.search(p, value) is not None),
        ]
    elif isinstance(value, int | float) and not isinstance(value, bool):
        checks = [
            ("minimum", lambda n: value >= n),
            ("maximum", lambda n: value <= n),
            ("exclusiveMinimum", lambda n: isinstance(n, bool) or value > n),
            ("exclusiveMaximum", lambda n: isinstance(n, bool) or value < n),
        ]
    elif isinstance(value, list):
        checks = [("minItems", lambda n: len(value) >= n), ("maxItems", lambda n: len(value) <= n)]
    return [
        f"{at}: {value!r} violates {key}={schema[key]!r}"
        for key, ok in checks
        if key in schema and not ok(schema[key])
    ]


def _walk_param(
    values: list[str], param: dict, spec: _Spec, base: Path | None, at: str
) -> list[str]:
    """Validate the wire strings of one path/query parameter (form style, exploded)."""
    schema, base = spec.merged(param.get("schema") or {}, base)
    if "array" in (_types(schema) or ()):
        items, items_base = spec.merged(schema.get("items") or {}, base)
        value: Any = [_from_wire(v, items) for v in values]
        return _walk(value, {**schema, "items": items}, spec, items_base, at)
    return _walk(_from_wire(values[-1], schema), schema, spec, base, at)


def _from_wire(raw: str, schema: dict) -> Any:
    types = _types(schema) or {"string"}
    for alt in schema.get("anyOf") or schema.get("oneOf") or []:
        types |= _types(alt) or set()
    if "integer" in types and re.fullmatch(r"-?\d+", raw):
        return int(raw)
    if "number" in types and re.fullmatch(r"-?\d+(\.\d+)?", raw):
        return float(raw)
    if "boolean" in types and raw in ("true", "false"):
        return raw == "true"
    return raw
