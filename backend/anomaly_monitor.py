import numpy as np
from typing import Dict, Any, List
from datetime import datetime, timedelta
import logging
from ..database import get_db
from ..config import settings

logger = logging.getLogger(__name__)

class AnomalyMonitor:
    """Statistical anomaly detection for transaction patterns"""

    def __init__(self, settings):
        self.settings = settings
        self.redis = None

    async def initialize(self):
        """Initialize Redis connection"""
        import aioredis
        self.redis = await aioredis.from_url(self.settings.redis_url)

    async def monitor(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor transaction for anomalies"""
        logger.debug(f"Running anomaly detection for transaction {transaction.get('id')}")

        # Check for velocity attacks
        velocity_check = await self._check_velocity(transaction)

        # Check for amount anomalies
        amount_anomaly = self._check_amount_anomaly(transaction)

        # Check for pattern deviation
        pattern_deviation = await self._check_pattern_deviation(transaction)

        # Calculate overall anomaly score
        anomaly_score = self._calculate_anomaly_score(velocity_check, amount_anomaly, pattern_deviation)

        is_anomalous = anomaly_score >= self.settings.anomaly_score_threshold

        return {
            "anomaly_score": round(anomaly_score, 4),
            "is_anomalous": is_anomalous,
            "flags": self._collect_flags(velocity_check, amount_anomaly, pattern_deviation),
            "details": {
                "velocity": velocity_check,
                "amount": amount_anomaly,
                "pattern": pattern_deviation
            }
        }

    async def _check_velocity(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Check for high-frequency transactions"""
        wallet = transaction.get("from_wallet")
        if not wallet or not self.redis:
            return {"score": 0.0, "flags": []}

        # Count transactions in last 60 seconds
        key = f"tx_velocity:{wallet}"
        count = await self.redis.incr(key)
        if count == 1:
            await self.redis.expire(key, 60)

        score = min(count * 0.1, 1.0)
        flags = []
        if count > 10:
            flags.append("high_frequency")
        if count > 20:
            flags.append("velocity_attack")

        return {"score": score, "flags": flags, "count": count}

    def _check_amount_anomaly(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Check if amount is anomalous based on historical patterns"""
        amount = float(transaction.get("amount", 0))

        # Simplified thresholds (in production, use statistical models)
        score = 0.0
        flags = []

        if amount > 50000:
            score = 0.9
            flags.append("extreme_amount")
        elif amount > 10000:
            score = 0.6
            flags.append("large_amount")
        elif amount < 0.01:
            score = 0.4
            flags.append("dust_amount")

        return {"score": score, "flags": flags}

    async def _check_pattern_deviation(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Check for deviation from typical transaction patterns"""
        # In production, this would query historical patterns from database
        # For now, return baseline
        return {"score": 0.0, "flags": []}

    def _calculate_anomaly_score(self, velocity: Dict, amount: Dict, pattern: Dict) -> float:
        """Calculate weighted anomaly score"""
        weights = {"velocity": 0.4, "amount": 0.4, "pattern": 0.2}
        return (
            velocity["score"] * weights["velocity"] +
            amount["score"] * weights["amount"] +
            pattern["score"] * weights["pattern"]
        )

    def _collect_flags(self, velocity: Dict, amount: Dict, pattern: Dict) -> List[str]:
        """Collect all anomaly flags"""
        flags = []
        flags.extend(velocity.get("flags", []))
        flags.extend(amount.get("flags", []))
        flags.extend(pattern.get("flags", []))
        return flags