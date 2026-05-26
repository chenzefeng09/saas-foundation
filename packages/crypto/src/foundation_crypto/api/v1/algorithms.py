"""Algorithm registry endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_crypto.api.dependencies import db_session
from foundation_crypto.domain.models import Algorithm
from foundation_crypto.schemas.algorithm import AlgorithmRead

router = APIRouter()


@router.get("/algorithms", operation_id="listAlgorithms")
async def list_algorithms(
    session: AsyncSession = Depends(db_session),
) -> list[AlgorithmRead]:
    stmt = select(Algorithm).where(Algorithm.deprecated == False).order_by(Algorithm.id)
    rows = (await session.execute(stmt)).scalars().all()
    return [AlgorithmRead.model_validate(r) for r in rows]
