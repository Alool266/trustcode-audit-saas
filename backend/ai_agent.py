import numpy as np
from typing import List, Dict, Any
from .config import settings
from .fraud_detector import FraudDetector
from .anomaly_monitor import AnomalyMonitor
from .compliance_auditor import ComplianceAuditor
import logging

logger = logging.getLogger(__name__)

class AIAgent:
    """Main AI Agent orchestrating fraud detection, anomaly monitoring, and compliance auditing"""

    def __init__(self, settings):
        self.settings = settings
        self.fraud_detector = FraudDetector(settings)
        self.anomaly_monitor = AnomalyMonitor(settings)
        self.compliance_auditor = ComplianceAuditor(settings)
        self.redis = None

    async def initialize(self):
        """Initialize AI Agent components"""
        logger.info("Initializing AI Agent...")
        # Initialize Redis connection
        import aioredis
        self.redis = await aioredis.from_url(self.settings.redis_url)
        logger.info("AI Agent initialized successfully")

    async def cleanup(self):
        """Cleanup resources"""
        if self.redis:
            await self.redis.close()
        logger.info("AI Agent cleanup complete")

    async def analyze_transaction(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive AI analysis on a transaction

        Args:
            transaction: Transaction data dictionary

        Returns:
            Analysis results with fraud score, anomalies, and compliance flags
        """
        logger.info(f"Analyzing transaction {transaction.get('id')}")

        # Run fraud detection
        fraud_result = await self.fraud_detector.detect(transaction)

        # Run anomaly monitoring
        anomaly_result = await self.anomaly_monitor.monitor(transaction)

        # Run compliance audit
        compliance_result = await self.compliance_auditor.audit(transaction)

        # Aggregate results
        overall_risk_score = self._aggregate_risk_score(
            fraud_result["risk_score"],
            anomaly_result["anomaly_score"],
            compliance_result["compliance_risk"]
        )

        return {
            "transaction_id": transaction.get("id"),
            "fraud_detection": fraud_result,
            "anomaly_monitoring": anomaly_result,
            "compliance_audit": compliance_result,
            "overall_risk_score": overall_risk_score,
            "is_suspicious": overall_risk_score >= self.settings.confidence_threshold,
            "requires_review": self._requires_human_review(overall_risk_score, fraud_result, anomaly_result)
        }

    def _aggregate_risk_score(self, fraud_score: float, anomaly_score: float, compliance_risk: float) -> float:
        """Aggregate multiple risk scores into overall risk score"""
        # Weighted average (can be tuned)
        weights = {"fraud": 0.4, "anomaly": 0.3, "compliance": 0.3}
        return (
            fraud_score * weights["fraud"] +
            anomaly_score * weights["anomaly"] +
            compliance_risk * weights["compliance"]
        )

    def _requires_human_review(self, overall_risk: float, fraud_result: Dict, anomaly_result: Dict) -> bool:
        """Determine if transaction requires human review"""
        if overall_risk >= 0.9:
            return True
        if fraud_result.get("is_suspicious") and anomaly_result.get("is_anomalous"):
            return True
        if compliance_result.get("violations"):
            return True
        return False