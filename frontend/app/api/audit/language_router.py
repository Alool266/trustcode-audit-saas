"""
Language Router
Routes files to the appropriate language analyzer.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Type
from analyzers.base_analyzer import BaseAnalyzer
from analyzers.python_analyzer import PythonAnalyzer


class LanguageRouter:
    """
    Routes files to the appropriate language analyzer based on file extension.
    """
    
    def __init__(self):
        self._analyzers: Dict[str, BaseAnalyzer] = {}
        self._register_default_analyzers()
    
    def _register_default_analyzers(self):
        """Register the default set of analyzers."""
        self.register_analyzer(PythonAnalyzer())
    
    def register_analyzer(self, analyzer: BaseAnalyzer):
        """
        Register a language analyzer.
        
        Args:
            analyzer: An instance of a class that extends BaseAnalyzer
        """
        for ext in analyzer.get_supported_extensions():
            self._analyzers[ext.lower()] = analyzer
    
    def get_analyzer(self, file_path: str) -> Optional[BaseAnalyzer]:
        """
        Get the appropriate analyzer for a file based on its extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            The appropriate analyzer, or None if no analyzer supports the file
        """
        ext = Path(file_path).suffix.lower()
        return self._analyzers.get(ext)
    
    def get_supported_extensions(self) -> List[str]:
        """Get list of all supported file extensions."""
        return list(self._analyzers.keys())
    
    def get_language_name(self, file_path: str) -> str:
        """
        Get the language name for a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Language name, or 'unknown' if not supported
        """
        analyzer = self.get_analyzer(file_path)
        if analyzer:
            return analyzer.get_language_name()
        return 'unknown'
    
    def analyze_file(self, source_code: str, file_path: str) -> dict:
        """
        Analyze a file using the appropriate analyzer.
        
        Args:
            source_code: The source code to analyze
            file_path: Path to the file
            
        Returns:
            Dictionary with analysis results
        """
        analyzer = self.get_analyzer(file_path)
        if not analyzer:
            return {
                "error": f"No analyzer available for file: {file_path}",
                "findings": [],
                "trust_score": 0
            }
        
        findings = analyzer.analyze(source_code, file_path)
        trust_score = analyzer.calculate_trust_score(findings)
        recommendation = analyzer.generate_recommendation(findings)
        
        return {
            "TrustScore": trust_score,
            "Findings": [f.to_dict() for f in findings],
            "PhD_Level_Recommendation": recommendation,
            "AuditMetadata": {
                "file": file_path,
                "language": analyzer.get_language_name(),
                "total_findings": len(findings)
            }
        }
    
    def get_analyzer_stats(self) -> dict:
        """Get statistics about registered analyzers."""
        stats = {
            "total_analyzers": len(set(self._analyzers.values())),
            "supported_extensions": self.get_supported_extensions(),
            "languages": list(set(a.get_language_name() for a in self._analyzers.values()))
        }
        return stats
