"""reindex_opensearch.py — 全量把 PG search.search_index 灌进 OpenSearch.

用途:
  1. 首次上线: 把存量 PG 数据灌进 OpenSearch (OS 之前没有这些数据).
  2. Mapping 变更后重建: 用 alias 切换实现零停机蓝绿 reindex.

Alias 切换流程 (零停机):
  1. 在 OS 创建新索引 foundation-search-v2 (同 mapping).
  2. 把 PG 数据 bulk 写入 v2.
  3. 原子切换 alias foundation-search: 从 v1 → v2.
  4. (可选) 删除旧索引 v1 (本脚本保留旧索引, 需手动删除).

简单模式 (--no-alias-swap):
  直接把数据 bulk 写入 alias 当前指向的具体索引, 不做版本切换.
  适合: 补数据/增量重跑, 不需要切换 mapping 时.

旧数据保守默认 (acl_team_ids/owner_id/visibility 缺失时):
  - visibility = "PRIVATE"   (宁可不可见, 不越权)
  - acl_team_ids = []
  - owner_id = ""  (从 metadata.owner_id 尝试推断; 推断不到则留空)
  保守原则: 宁可重新显式授权, 也不意外开放权限.

用法:
  cd packages/search
  PYTHONPATH=src python3 scripts/reindex_opensearch.py [OPTIONS]

  --batch-size N     每批 bulk 写入文档数 (default: 500)
  --os-url URL       OpenSearch URL (default: $SEARCH_OPENSEARCH_URL or http://127.0.0.1:9200)
  --db-dsn DSN       Postgres DSN (default: $SEARCH_DB_DSN_MIGRATOR or $SEARCH_DB_DSN)
  --new-index NAME   新索引名 (alias 切换模式用, default: foundation-search-v2)
  --alias NAME       alias 名 (default: foundation-search)
  --no-alias-swap    跳过 alias 切换, 直接写入 alias 当前指向的索引
  --dry-run          只读 PG, 不写 OS (用于测试分页逻辑)
  --tenant-id ID     只 reindex 指定 tenant (调试/补数据用)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any

import httpx

# ─── 日志 ─────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stderr,
)
log = logging.getLogger("reindex")


# ─── CLI 参数 ─────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Reindex PG search.search_index → OpenSearch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--batch-size", type=int, default=500,
                   help="每批 bulk 写入文档数 (default: 500)")
    p.add_argument("--os-url", default=None,
                   help="OpenSearch URL (default: $SEARCH_OPENSEARCH_URL or http://127.0.0.1:9200)")
    p.add_argument("--db-dsn", default=None,
                   help="Postgres asyncpg DSN (default: $SEARCH_DB_DSN_MIGRATOR or $SEARCH_DB_DSN)")
    p.add_argument("--new-index", default="foundation-search-v2",
                   help="新索引名 (alias 切换模式用, default: foundation-search-v2)")
    p.add_argument("--alias", default="foundation-search",
                   help="alias 名 (default: foundation-search)")
    p.add_argument("--no-alias-swap", action="store_true",
                   help="跳过 alias 切换, 直接写入 alias 当前指向的索引")
    p.add_argument("--dry-run", action="store_true",
                   help="只读 PG, 不写 OS")
    p.add_argument("--tenant-id", default=None,
                   help="只 reindex 指定 tenant")
    return p.parse_args()


# ─── OpenSearch helpers (同步 httpx, 避免 opensearchpy 额外依赖) ───────────────

_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=30.0, pool=5.0)

# OpenSearch index mapping — 与 search-init 容器保持一致
INDEX_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 1,
        "analysis": {
            "analyzer": {
                "foundation_default": {
                    "type": "standard",
                    "stopwords": "_none_",
                }
            }
        },
    },
    "mappings": {
        "properties": {
            "tenant_id":      {"type": "keyword"},
            "resource_type":  {"type": "keyword"},
            "resource_id":    {"type": "keyword"},
            "title":          {"type": "text", "analyzer": "foundation_default", "boost": 2},
            "content":        {"type": "text", "analyzer": "foundation_default"},
            "tags":           {"type": "keyword"},
            "acl_user_ids":   {"type": "keyword"},
            "acl_team_ids":   {"type": "keyword"},
            "owner_id":       {"type": "keyword"},
            "visibility":     {"type": "keyword"},
            "sensitivity":    {"type": "keyword"},
            "sensitivity_rank": {"type": "integer"},
            "indexed_at":     {"type": "date"},
        }
    },
}


def os_request(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    body: Any = None,
    expected_statuses: tuple[int, ...] = (200, 201),
    ignore_404: bool = False,
) -> dict[str, Any]:
    """同步 OpenSearch HTTP 请求."""
    url = path  # path 由调用方拼好
    resp = client.request(
        method,
        url,
        json=body,
        headers={"Content-Type": "application/json"},
    )
    if ignore_404 and resp.status_code == 404:
        return {}
    if resp.status_code not in expected_statuses:
        raise RuntimeError(
            f"OS {method} {url} → {resp.status_code}: {resp.text[:300]}"
        )
    try:
        return resp.json()
    except ValueError:
        return {}


def get_alias_target(client: httpx.Client, base: str, alias: str) -> str | None:
    """返回 alias 当前指向的具体索引名; 不存在返回 None."""
    try:
        resp = client.get(f"{base}/_alias/{alias}")
        if resp.status_code == 404:
            return None
        data = resp.json()
        # data: {index_name: {aliases: {alias_name: {}}}}
        for index_name in data:
            if alias in data[index_name].get("aliases", {}):
                return index_name
        return None
    except Exception as e:
        log.warning(f"get_alias_target failed: {e}")
        return None


def create_index(client: httpx.Client, base: str, index_name: str) -> None:
    """创建索引 (若已存在则跳过)."""
    resp = client.head(f"{base}/{index_name}")
    if resp.status_code == 200:
        log.info(f"Index {index_name!r} already exists, skipping creation")
        return
    log.info(f"Creating index {index_name!r} ...")
    os_request(
        client, "PUT", f"{base}/{index_name}",
        body=INDEX_MAPPING,
        expected_statuses=(200, 201),
    )
    log.info(f"Index {index_name!r} created")


def bulk_index(
    client: httpx.Client,
    base: str,
    write_index: str,
    docs: list[tuple[str, dict[str, Any]]],  # (doc_id, doc)
) -> tuple[int, int]:
    """Bulk 写入文档, 返回 (indexed_count, error_count)."""
    if not docs:
        return 0, 0

    lines: list[str] = []
    for doc_id, doc in docs:
        meta = json.dumps({"index": {"_index": write_index, "_id": doc_id}})
        lines.append(meta)
        lines.append(json.dumps(doc))
    body_str = "\n".join(lines) + "\n"

    resp = client.post(
        f"{base}/_bulk",
        content=body_str.encode(),
        headers={"Content-Type": "application/x-ndjson"},
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Bulk request failed: {resp.status_code}: {resp.text[:300]}")

    result = resp.json()
    error_count = 0
    indexed_count = 0
    if result.get("errors"):
        for item in result.get("items", []):
            action_result = item.get("index", {})
            if action_result.get("error"):
                error_count += 1
                log.error(f"Bulk error on {action_result.get('_id')}: {action_result['error']}")
            else:
                indexed_count += 1
    else:
        indexed_count = len(docs)

    return indexed_count, error_count


def swap_alias(
    client: httpx.Client,
    base: str,
    alias: str,
    old_index: str | None,
    new_index: str,
) -> None:
    """原子切换 alias: old_index → new_index.

    使用 _aliases API 原子操作: 同时 remove(old) + add(new).
    zero-downtime: 在 OS 看来, alias 切换在单个操作内完成.
    """
    actions: list[dict[str, Any]] = []
    if old_index and old_index != new_index:
        actions.append({"remove": {"index": old_index, "alias": alias}})
    actions.append({"add": {"index": new_index, "alias": alias}})

    log.info(f"Swapping alias {alias!r}: {old_index!r} → {new_index!r}")
    os_request(
        client, "POST", f"{base}/_aliases",
        body={"actions": actions},
        expected_statuses=(200, 201),
    )
    log.info(f"Alias {alias!r} now points to {new_index!r}")


# ─── PG 读取 (asyncpg 直连; 不走 ORM session 避免 tenant context 要求) ─────────

async def stream_pg_rows(
    dsn: str,
    batch_size: int,
    tenant_id_filter: str | None,
) -> list[dict[str, Any]]:
    """分页读取 search.search_index (deleted_at IS NULL).

    返回完整行列表 (内存中分批处理由调用方控制).
    使用游标分页避免大结果集 OOM.
    """
    try:
        import asyncpg  # type: ignore[import]
    except ImportError:
        log.error("asyncpg not installed. Install with: pip install asyncpg")
        sys.exit(1)

    # asyncpg 的 DSN 格式: postgresql://user:pass@host/db
    # 如果是 SQLAlchemy 格式 (postgresql+asyncpg://...), 转换
    pg_dsn = dsn.replace("postgresql+asyncpg://", "postgresql://")

    log.info(f"Connecting to Postgres: {_mask_dsn(pg_dsn)}")
    conn: asyncpg.Connection = await asyncpg.connect(pg_dsn)
    try:
        where = "deleted_at IS NULL"
        params: list[Any] = []
        if tenant_id_filter:
            where += " AND tenant_id = $1"
            params.append(tenant_id_filter)

        # 用游标分页 (keyset on id) 避免大表 OFFSET 慢查
        order_col = "id"
        last_id: str | None = None
        all_rows: list[dict[str, Any]] = []
        page = 0

        while True:
            page_where = where
            page_params = list(params)
            if last_id is not None:
                idx = len(page_params) + 1
                page_where += f" AND {order_col} > ${idx}"
                page_params.append(last_id)

            query = f"""
                SELECT
                    id, tenant_id, resource_type, resource_id,
                    title, content, tags,
                    acl_user_ids, acl_team_ids,
                    owner_id, visibility,
                    sensitivity, sensitivity_rank,
                    metadata,
                    indexed_at
                FROM search.search_index
                WHERE {page_where}
                ORDER BY {order_col}
                LIMIT {batch_size}
            """
            rows = await conn.fetch(query, *page_params)
            if not rows:
                break

            page += 1
            batch_rows = [dict(r) for r in rows]
            all_rows.extend(batch_rows)
            last_id = batch_rows[-1]["id"]
            log.info(f"Fetched page {page}: {len(batch_rows)} rows (total so far: {len(all_rows)})")

        return all_rows
    finally:
        await conn.close()


def _mask_dsn(dsn: str) -> str:
    """隐藏 DSN 中的密码."""
    import re
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", dsn)


# ─── 保守默认处理 ──────────────────────────────────────────────────────────────

def apply_conservative_defaults(row: dict[str, Any]) -> dict[str, Any]:
    """对旧数据缺失的 ACL 字段补保守默认值.

    保守原则: 宁可用户找不到资源, 也不意外开放权限.
      - visibility 缺失/None → "PRIVATE"
      - acl_team_ids 缺失/None → []
      - owner_id 缺失/None → 从 metadata.owner_id 推断; 推断不到则 ""
    """
    metadata: dict[str, Any] = row.get("metadata") or {}

    # visibility
    visibility = row.get("visibility")
    if not visibility:
        # 尝试从 metadata 推断
        visibility = metadata.get("visibility") or "PRIVATE"

    # acl_team_ids
    acl_team_ids = row.get("acl_team_ids") or []

    # owner_id
    owner_id = row.get("owner_id")
    if not owner_id:
        owner_id = (
            metadata.get("owner_id")
            or metadata.get("created_by")
            or ""
        )

    return {
        **row,
        "visibility": visibility,
        "acl_team_ids": acl_team_ids,
        "owner_id": owner_id,
    }


def build_os_doc(row: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """把 PG 行转成 OS 文档, 返回 (doc_id, doc)."""
    row = apply_conservative_defaults(row)

    tenant_id = row["tenant_id"]
    resource_type = row["resource_type"]
    resource_id = row["resource_id"]
    doc_id = f"{tenant_id}:{resource_type}:{resource_id}"

    # indexed_at: 转 ISO 字符串 (asyncpg 返回 datetime)
    indexed_at = row.get("indexed_at")
    if isinstance(indexed_at, datetime):
        indexed_at_str = indexed_at.astimezone(UTC).isoformat()
    else:
        indexed_at_str = str(indexed_at) if indexed_at else datetime.now(UTC).isoformat()

    doc = {
        "tenant_id": tenant_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "title": row["title"],
        "content": row["content"],
        "tags": row.get("tags") or [],
        "acl_user_ids": row.get("acl_user_ids") or [],
        "acl_team_ids": row["acl_team_ids"],
        "owner_id": row["owner_id"],
        "visibility": row["visibility"],
        "sensitivity": row.get("sensitivity") or "L3",
        "sensitivity_rank": int(row.get("sensitivity_rank") or 3),
        "indexed_at": indexed_at_str,
    }
    return doc_id, doc


# ─── 主逻辑 ───────────────────────────────────────────────────────────────────

async def main() -> None:
    args = parse_args()

    # ── 解析配置 ──
    os_url = (
        args.os_url
        or os.environ.get("SEARCH_OPENSEARCH_URL")
        or "http://127.0.0.1:9200"
    ).rstrip("/")

    db_dsn = (
        args.db_dsn
        or os.environ.get("SEARCH_DB_DSN_MIGRATOR")
        or os.environ.get("SEARCH_DB_DSN")
    )
    if not db_dsn:
        log.error(
            "Postgres DSN not specified. "
            "Set --db-dsn, SEARCH_DB_DSN_MIGRATOR, or SEARCH_DB_DSN."
        )
        sys.exit(1)

    alias = args.alias
    new_index = args.new_index
    batch_size = args.batch_size
    dry_run = args.dry_run
    no_alias_swap = args.no_alias_swap
    tenant_filter = args.tenant_id

    log.info("=" * 60)
    log.info("reindex_opensearch.py — OpenSearch 全量 reindex")
    log.info("=" * 60)
    log.info(f"  OS URL:      {os_url}")
    log.info(f"  DB DSN:      {_mask_dsn(db_dsn)}")
    log.info(f"  Alias:       {alias}")
    log.info(f"  New index:   {new_index}")
    log.info(f"  Batch size:  {batch_size}")
    log.info(f"  Alias swap:  {not no_alias_swap}")
    log.info(f"  Dry run:     {dry_run}")
    log.info(f"  Tenant filter: {tenant_filter or '(all)'}")
    log.info("")

    # ── 检查 OS 健康 ──
    with httpx.Client(timeout=_TIMEOUT) as client:
        try:
            health_resp = client.get(f"{os_url}/_cluster/health")
            health = health_resp.json()
            status = health.get("status", "unknown")
            log.info(f"OpenSearch cluster status: {status}")
            if status not in ("green", "yellow"):
                log.error(f"OpenSearch not healthy (status={status}), aborting")
                sys.exit(1)
        except Exception as e:
            log.error(f"Cannot reach OpenSearch at {os_url}: {e}")
            sys.exit(1)

        # ── 确定写入目标索引 ──
        current_alias_target = get_alias_target(client, os_url, alias)
        log.info(f"Current alias {alias!r} → {current_alias_target!r}")

        if no_alias_swap:
            # 直接写入 alias 当前指向的索引
            if not current_alias_target:
                log.error(
                    f"Alias {alias!r} does not exist and --no-alias-swap is set. "
                    f"Run without --no-alias-swap to create a new index."
                )
                sys.exit(1)
            write_index = current_alias_target
            log.info(f"--no-alias-swap: writing directly to {write_index!r}")
        else:
            # 别名切换模式: 创建新索引
            write_index = new_index
            if not dry_run:
                create_index(client, os_url, write_index)

        # ── 读 PG ──
        log.info("")
        log.info("Reading from Postgres ...")
        t0 = time.time()
        rows = await stream_pg_rows(db_dsn, batch_size, tenant_filter)
        t1 = time.time()
        log.info(f"Read {len(rows)} rows from PG in {t1-t0:.1f}s")

        if not rows:
            log.info("No rows to reindex.")
            if not no_alias_swap and not dry_run:
                # 新索引已建但没数据, 仍要切 alias (确保 alias 指向新索引)
                swap_alias(client, os_url, alias, current_alias_target, write_index)
            log.info("Done (no data).")
            return

        if dry_run:
            log.info(f"[DRY RUN] Would write {len(rows)} docs to {write_index!r}. Exiting.")
            return

        # ── Bulk 写入 ──
        log.info("")
        log.info(f"Bulk indexing {len(rows)} docs → {write_index!r} (batch={batch_size}) ...")
        total_indexed = 0
        total_errors = 0
        t2 = time.time()

        for i in range(0, len(rows), batch_size):
            batch = rows[i:i + batch_size]
            doc_pairs = [build_os_doc(row) for row in batch]
            indexed, errors = bulk_index(client, os_url, write_index, doc_pairs)
            total_indexed += indexed
            total_errors += errors
            log.info(
                f"  Batch {i // batch_size + 1}: "
                f"{indexed} indexed, {errors} errors "
                f"(cumulative: {total_indexed} ok / {total_errors} err)"
            )

        t3 = time.time()
        log.info(
            f"Bulk done in {t3-t2:.1f}s: "
            f"{total_indexed} indexed, {total_errors} errors"
        )

        if total_errors > 0:
            log.error(
                f"{total_errors} bulk errors occurred. "
                f"Check logs above. NOT swapping alias."
            )
            sys.exit(1)

        # ── 刷新索引 (确保文档可搜索) ──
        log.info(f"Refreshing index {write_index!r} ...")
        os_request(client, "POST", f"{os_url}/{write_index}/_refresh", expected_statuses=(200, 201))

        # ── Alias 切换 ──
        if not no_alias_swap:
            swap_alias(client, os_url, alias, current_alias_target, write_index)
            if current_alias_target and current_alias_target != write_index:
                log.info(
                    f"Old index {current_alias_target!r} is still present. "
                    f"Verify traffic is clean, then delete manually:\n"
                    f"  curl -X DELETE {os_url}/{current_alias_target}"
                )
        else:
            log.info(f"--no-alias-swap: alias {alias!r} unchanged → {write_index!r}")

        # ── 验证 ──
        verify_resp = client.get(f"{os_url}/{write_index}/_count")
        if verify_resp.status_code == 200:
            count = verify_resp.json().get("count", "?")
            log.info(f"Verification: {write_index!r} doc count = {count}")

        log.info("")
        log.info(
            f"Reindex complete: {total_indexed} docs written to {write_index!r}. "
            f"Alias {alias!r} → {write_index!r}."
        )


if __name__ == "__main__":
    asyncio.run(main())
