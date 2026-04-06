from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from ..database import get_db
from ..ai_agent import AIAgent
from ..config import settings
import uuid
from datetime import datetime

router = APIRouter()

@router.post("/transaction")
async def audit_transaction(
    request: Request,
    transaction: dict,
    db: AsyncSession = Depends(get_db)
):
    """
    Audit a transaction using AI agent

    Request body:
    {
        "id": "uuid",
        "from_wallet": "wallet_address",
        "to_wallet": "wallet_address",
        "amount": 1000.00,
        "currency": "USD",
        "timestamp": "2024-01-01T00:00:00Z",
        "from_country": "US",
        "to_country": "US",
        "kyc_status": "verified",
        "kyc_tier": 2
    }
    """
    try:
        # Get AI agent from app state
        ai_agent: AIAgent = request.app.state.ai_agent

        # Run AI analysis
        analysis = await ai_agent.analyze_transaction(transaction)

        # Store analysis result in database
        await db.execute(
            text("""
                INSERT INTO audit_logs
                (id, transaction_id, analysis_timestamp, risk_score, is_suspicious, flags, details)
                VALUES (:id, :transaction_id, :timestamp, :risk_score, :is_suspicious, :flags, :details)
            """),
            {
                "id": uuid.uuid4(),
                "transaction_id": transaction.get("id"),
                "timestamp": datetime.utcnow(),
                "risk_score": analysis["overall_risk_score"],
                "is_suspicious": analysis["is_suspicious"],
                "flags": str(analysis),
                "details": analysis
            }
        )

        return analysis

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/report/{wallet_id}")
async def get_anomaly_report(
    wallet_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get anomaly report for a wallet"""
    try:
        # Query recent audit logs for wallet
        result = await db.execute(
            text("""
                SELECT COUNT(*) as total,
                       AVG(risk_score) as avg_risk,
                       MAX(risk_score) as max_risk,
                       COUNT(CASE WHEN is_suspicious THEN 1 END) as suspicious_count
                FROM audit_logs al
                JOIN transactions t ON al.transaction_id = t.id
                WHERE t.from_wallet = :wallet_id
                AND al.analysis_timestamp > NOW() - INTERVAL '24 hours'
            """),
            {"wallet_id": wallet_id}
        )
        stats = result.fetchone()

        return {
            "wallet_id": wallet_id,
            "period": "24h",
            "total_audits": stats[0] if stats[0] else 0,
            "avg_risk_score": float(stats[1]) if stats[1] else 0.0,
            "max_risk_score": float(stats[2]) if stats[2] else 0.0,
            "suspicious_count": stats[3] if stats[3] else 0,
            "requires_manual_review": stats[3] > 0 if stats[3] else False
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/compliance")
async def run_compliance_audit(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Run full compliance audit"""
    try:
        ai_agent: AIAgent = request.app.state.ai_agent

        # Get all pending transactions
        result = await db.execute(
            text("SELECT * FROM transactions WHERE status = 'pending'")
        )
        transactions = result.fetchall()

        audit_results = []
        for tx in transactions:
            tx_dict = dict(zip(result.keys(), tx))
            analysis = await ai_agent.analyze_transaction(tx_dict)
            audit_results.append(analysis)

        return {
            "audit_timestamp": datetime.utcnow(),
            "total_transactions": len(audit_results),
            "suspicious_count": sum(1 for r in audit_results if r["is_suspicious"]),
            "results": audit_results
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))