"""
Base Analyzer Interface
Abstract base class for all language analyzers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class AuditFinding:
    """Represents a single audit finding."""
    category: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    message: str
    line: int
    column: int = 1
    file_path: str = ""
    snippet: str = ""
    recommendation: str = ""
    cwe_id: str = ""  # Common Weakness Enumeration ID
    cvss_score: float = 0.0  # 0.0 - 10.0
    fix_suggestion: str = ""
    related_findings: List[int] = field(default_factory=list)
    language: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "file_path": self.file_path,
            "snippet": self.snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "fix_suggestion": self.fix_suggestion,
            "related_findings": self.related_findings,
            "language": self.language
        }


@dataclass
class ProjectSummary:
    """Summary of a project audit."""
    total_files: int = 0
    total_lines: int = 0
    languages: List[str] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "languages": self.languages,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count
        }


@dataclass
class AuditResult:
    """Complete audit result."""
    trust_score: int
    findings: List[AuditFinding]
    phd_level_recommendation: str
    audit_metadata: Dict[str, Any]
    project_summary: Optional[ProjectSummary] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "TrustScore": self.trust_score,
            "Findings": [f.to_dict() for f in self.findings],
            "PhD_Level_Recommendation": self.phd_level_recommendation,
            "AuditMetadata": self.audit_metadata
        }
        if self.project_summary:
            result["ProjectSummary"] = self.project_summary.to_dict()
        return result


class BaseAnalyzer(ABC):
    """Abstract base class for all language analyzers."""
    
    @abstractmethod
    def analyze(self, source_code: str, file_path: str = "") -> List[AuditFinding]:
        """
        Analyze source code and return a list of findings.
        
        Args:
            source_code: The source code to analyze
            file_path: Path to the source file (for context)
            
        Returns:
            List of AuditFinding objects
        """
        pass
    
    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """Return list of file extensions this analyzer supports."""
        pass
    
    @abstractmethod
    def get_language_name(self) -> str:
        """Return the name of the language this analyzer handles."""
        pass
    
    def supports_file(self, file_path: str) -> bool:
        """Check if this analyzer supports the given file."""
        ext = '.' + file_path.rsplit('.', 1)[-1].lower() if '.' in file_path else ''
        return ext in self.get_supported_extensions()
    
    def calculate_cvss_score(self, finding: AuditFinding) -> float:
        """
        Calculate CVSS-like score for a finding.
        Override in subclasses for language-specific scoring.
        """
        base_scores = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.5
        }
        return base_scores.get(finding.severity.lower(), 5.0)
    
    def calculate_trust_score(self, findings: List) -> int:
        """
        Calculate overall trust score (0-100) based on findings.
        Handles both AuditFinding objects and dictionaries.
        """
        score = 100
        
        severity_weights = {
            'critical': 20,
            'high': 10,
            'medium': 5,
            'low': 2,
            'info': 0
        }
        
        for finding in findings:
            # Handle both AuditFinding objects and dictionaries
            if isinstance(finding, dict):
                severity = finding.get('severity', 'medium').lower()
            else:
                severity = finding.severity.lower()
            weight = severity_weights.get(severity, 5)
            score -= weight
        
        return max(0, min(100, score))
    
    def generate_recommendation(self, findings: List[AuditFinding]) -> str:
        """Generate a PhD-level recommendation based on findings."""
        critical_count = sum(1 for f in findings if f.severity.lower() == 'critical')
        high_count = sum(1 for f in findings if f.severity.lower() == 'high')
        
        if critical_count > 0:
            return f"CRITICAL INTERVENTION REQUIRED: {critical_count} critical issue(s) detected. Immediate refactoring is essential before production deployment. Focus on security vulnerabilities and API correctness. The current code exhibits patterns consistent with AI hallucination artifacts."
        elif high_count > 0:
            return f"HIGH PRIORITY REMEDIATION: {high_count} high-severity issue(s) detected. Address security vulnerabilities and error handling patterns before deployment. Consider implementing comprehensive input validation and secure coding practices."
        elif findings:
            return f"MODERATE IMPROVEMENTS RECOMMENDED: {len(findings)} issue(s) detected. Focus on code quality improvements and best practices adoption. Consider implementing proper error handling and removing magic numbers."
        else:
            return "EXCELLENT: No significant issues detected. The code follows good practices. Continue maintaining code quality and consider implementing additional security measures for production deployment."
