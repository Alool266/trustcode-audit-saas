from fastapi import APIRouter, Depends
from ..config import settings
import aioredis
from sqlalchemy import text
from .database import get_db

router = APIRouter()

@router.get("/health")
async def health_check(db=Depends(get_db)):
    """Health check endpoint"""
    try:
        # Check database connection
        result = await db.execute(text("SELECT 1"))
        db_status = "healthy" if result.scalar() == 1 else "unhealthy"

        # Check Redis connection
        redis = aioredis.from_url(settings.redis_url)
        await redis.ping()
        await redis.close()
        redis_status = "healthy"
    except Exception as e:
        db_status = "unhealthy"
        redis_status = f"error: {str(e)}"

    return {
        "status": "healthy" if db_status == "healthy" and redis_status == "healthy" else "unhealthy",
        "database": db_status,
        "redis": redis_status,
        "service": "python-ai-agent"
    }