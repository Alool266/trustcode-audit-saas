from typing import Dict, Any, List
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ComplianceAuditor:
    """Regulatory compliance auditing for financial transactions"""

    def __init__(self, settings):
        self.settings = settings
        # AML thresholds
        self.aml_threshold = 10000  # USD
        self.sanctioned_countries = ["KP", "IR", "SY", "CU"]

    async def audit(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Perform compliance audit on transaction"""
        logger.debug(f"Running compliance audit for transaction {transaction.get('id')}")

        # Check AML requirements
        aml_check = self._check_aml(transaction)

        # Check sanctions
        sanctions_check = self._check_sanctions(transaction)

        # Check KYC requirements
        kyc_check = self._check_kyc(transaction)

        # Calculate compliance risk
        compliance_risk = self._calculate_compliance_risk(aml_check, sanctions_check, kyc_check)

        # Collect violations
        violations = self._collect_violations(aml_check, sanctions_check, kyc_check)

        return {
            "compliance_risk": round(compliance_risk, 4),
            "is_compliant": len(violations) == 0,
            "violations": violations,
            "details": {
                "aml": aml_check,
                "sanctions": sanctions_check,
                "kyc": kyc_check
            }
        }

    def _check_aml(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Anti-Money Laundering checks"""
        amount = float(transaction.get("amount", 0))
        flags = []
        requires_reporting = False

        # CTR (Currency Transaction Report) threshold
        if amount >= self.aml_threshold:
            flags.append("ctr_required")
            requires_reporting = True

        # Structuring detection (multiple transactions just below threshold)
        if 9000 <= amount < self.aml_threshold:
            flags.append("potential_structuring")

        return {
            "flags": flags,
            "requires_reporting": requires_reporting,
            "amount": amount
        }

    def _check_sanctions(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Sanctions list checks"""
        # In production, check against OFAC, UN, EU sanctions lists
        flags = []
        is_sanctioned = False

        # Placeholder for country checks
        from_country = transaction.get("from_country", "")
        to_country = transaction.get("to_country", "")

        if from_country in self.sanctioned_countries:
            flags.append(f"sanctioned_country_from:{from_country}")
            is_sanctioned = True

        if to_country in self.sanctioned_countries:
            flags.append(f"sanctioned_country_to:{to_country}")
            is_sanctioned = True

        return {
            "flags": flags,
            "is_sanctioned": is_sanctioned
        }

    def _check_kyc(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Know Your Customer checks"""
        flags = []
        is_verified = True

        # Check if wallet has completed KYC
        kyc_status = transaction.get("kyc_status", "unknown")
        if kyc_status == "unverified":
            flags.append("unverified_wallet")
            is_verified = False
        elif kyc_status == "pending":
            flags.append("pending_kyc")

        # Check transaction limits based on KYC tier
        kyc_tier = transaction.get("kyc_tier", 0)
        amount = float(transaction.get("amount", 0))

        tier_limits = {0: 1000, 1: 5000, 2: 25000, 3: float('inf')}
        limit = tier_limits.get(kyc_tier, 0)

        if amount > limit:
            flags.append(f"exceeds_kyc_limit:tier_{kyc_tier}")

        return {
            "flags": flags,
            "is_verified": is_verified,
            "kyc_status": kyc_status,
            "kyc_tier": kyc_tier
        }

    def _calculate_compliance_risk(self, aml: Dict, sanctions: Dict, kyc: Dict) -> float:
        """Calculate overall compliance risk score"""
        risk = 0.0

        # AML risk
        if aml.get("requires_reporting"):
            risk += 0.3
        if "potential_structuring" in aml.get("flags", []):
            risk += 0.4

        # Sanctions risk (highest priority)
        if sanctions.get("is_sanctioned"):
            risk += 0.8

        # KYC risk
        if not kyc.get("is_verified"):
            risk += 0.3
        if "exceeds_kyc_limit" in str(kyc.get("flags", [])):
            risk += 0.2

        return min(risk, 1.0)

    def _collect_violations(self, aml: Dict, sanctions: Dict, kyc: Dict) -> List[str]:
        """Collect all compliance violations"""
        violations = []
        violations.extend(aml.get("flags", []))
        violations.extend(sanctions.get("flags", []))
        violations.extend(kyc.get("flags", []))
        return violations