import numpy as np
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class FraudDetector:
    """ML-based fraud detection using ensemble methods"""

    def __init__(self, settings):
        self.settings = settings
        self.model = None
        # In production, load a pre-trained model
        # self.model = self._load_model()

    async def detect(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Detect fraudulent patterns in transaction"""
        logger.debug(f"Running fraud detection for transaction {transaction.get('id')}")

        # Extract features
        features = self._extract_features(transaction)

        # Calculate risk score (simplified heuristic for demo)
        risk_score = self._calculate_risk_score(features)

        # Determine if suspicious
        is_suspicious = risk_score >= self.settings.confidence_threshold

        # Generate flags
        flags = self._generate_flags(features, risk_score)

        return {
            "risk_score": round(risk_score, 4),
            "is_suspicious": is_suspicious,
            "flags": flags,
            "model_version": "1.0.0"
        }

    def _extract_features(self, transaction: Dict[str, Any]) -> Dict[str, float]:
        """Extract numerical features from transaction"""
        amount = float(transaction.get("amount", 0))
        hour = transaction.get("timestamp", "").hour if hasattr(transaction.get("timestamp", ""), "hour") else 12

        return {
            "amount": amount,
            "amount_log": np.log1p(amount),
            "hour": hour,
            "is_night": 1 if (hour < 6 or hour > 22) else 0,
            "is_weekend": 1 if transaction.get("timestamp", "").weekday() >= 5 else 0,
        }

    def _calculate_risk_score(self, features: Dict[str, float]) -> float:
        """Calculate fraud risk score based on features"""
        score = 0.0

        # Large amount
        if features["amount"] > 10000:
            score += 0.4
        elif features["amount"] > 5000:
            score += 0.2

        # Night transactions
        if features["is_night"]:
            score += 0.2

        # High-risk countries would add more here

        return min(score, 1.0)

    def _generate_flags(self, features: Dict[str, float], risk_score: float) -> List[str]:
        """Generate human-readable flags"""
        flags = []
        if features["amount"] > 10000:
            flags.append("large_transaction")
        if features["is_night"]:
            flags.append("off_hours_transaction")
        if risk_score >= 0.8:
            flags.append("high_risk_score")
        return flags