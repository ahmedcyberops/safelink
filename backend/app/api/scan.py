"""Scan API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.schemas.scan import ErrorResponse, ScanRequest, ScanResponse
from app.services.rate_limiter import RateLimitExceeded, check_rate_limit
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scan", tags=["scan"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post(
    "",
    response_model=ScanResponse,
    responses={
        400: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
)
async def create_scan(
    body: ScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Submit a URL for security analysis."""
    client_ip = _get_client_ip(request)
    try:
        await check_rate_limit(client_ip)
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "code": "rate_limit_exceeded",
                "message": f"Too many requests. Please wait {exc.retry_after} seconds.",
            },
            headers={"Retry-After": str(exc.retry_after)},
        )

    service = ScanService(db)
    scan = await service.create_scan(body.url, client_ip)
    result = await service.run_scan(scan)
    return result


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve a scan result by ID."""
    service = ScanService(db)
    result = await service.get_scan(scan_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "not_found",
                "code": "scan_not_found",
                "message": "Scan not found or has expired.",
            },
        )
    return result
