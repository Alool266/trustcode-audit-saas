"""
False Positive Reducer
Context-aware analysis to reduce false positives in audit findings.
"""

import re
from pathlib import Path
from typing import List, Set
from .base_analyzer import AuditFinding


class FalsePositiveReducer:
    """
    Reduces false positives by applying context-aware filters.
    """
    
    # Patterns to identify test files
    TEST_FILE_PATTERNS = [
        r'^test_.*\.py$',
        r'.*_test\.py$',
        r'^.*\.test\.py$',
        r'^tests?/',
        r'/tests?/',
        r'__tests__',
        r'__test__',
        r'spec\.py$',
    ]
    
    # Patterns to identify mock/fake/test data
    MOCK_INDICATORS = [
        r'mock_',
        r'fake_',
        r'fixture_',
        r'dummy_',
        r'stub_',
        r'example_',
        r'sample_',
        r'test_data',
        r'TEST_',
        r'MOCK_',
        r'FAKE_',
    ]
    
    # Patterns to identify example/documentation code
    EXAMPLE_DIRS = [
        'example',
        'examples',
        'doc',
        'docs',
        'documentation',
        'samples',
        'tutorial',
        'guide',
    ]
    
    # Suppression comment patterns
    SUPPRESSION_PATTERNS = [
        r'#\s*nosec',
        r'#\s*trustcode-ignore',
        r'#\s*noqa',
        r'#\s*lint\s*ignore',
        r'//\s*nosec',
        r'//\s*trustcode-ignore',
    ]
    
    def __init__(self):
        self.test_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.TEST_FILE_PATTERNS]
        self.mock_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.MOCK_INDICATORS]
        self.suppression_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.SUPPRESSION_PATTERNS]
    
    def filter_findings(self, findings: List, file_path: str) -> List:
        """
        Filter out likely false positives from the findings list.
        
        Args:
            findings: List of audit findings (can be AuditFinding objects or dicts)
            file_path: Path to the source file
            
        Returns:
            Filtered list of findings
        """
        filtered = []
        for finding in findings:
            if not self.is_likely_false_positive(finding, file_path):
                filtered.append(finding)
        return filtered
    
    def is_likely_false_positive(self, finding, file_path: str) -> bool:
        """
        Determine if a finding is likely a false positive.
        """
        # Check if file is a test file
        if self.is_test_file(file_path):
            return True
        
        # Check if finding is in an example/documentation directory
        if self.is_example_file(file_path):
            return True
        
        # Check if variable/method name indicates mock/test data
        if self.is_mock_indicator(finding):
            return True
        
        # Check for suppression comments in the snippet
        if self.has_suppression_comment(finding):
            return True
        
        # Check if finding is in a fixture/seed file
        if self.is_fixture_file(file_path):
            return True
        
        return False
    
    def is_test_file(self, file_path: str) -> bool:
        """Check if the file is a test file based on name/path."""
        path = Path(file_path)
        
        # Check filename patterns
        for pattern in self.test_patterns_compiled:
            if pattern.match(path.name):
                return True
        
        # Check if any parent directory indicates tests
        for part in path.parts:
            for pattern in self.test_patterns_compiled:
                if pattern.match(part):
                    return True
        
        return False
    
    def is_example_file(self, file_path: str) -> bool:
        """Check if the file is in an examples or documentation directory."""
        path = Path(file_path)
        for part in path.parts:
            if part.lower() in self.EXAMPLE_DIRS:
                return True
        return False
    
    def is_fixture_file(self, file_path: str) -> bool:
        """Check if the file is a fixture/seed file."""
        path = Path(file_path)
        fixture_patterns = [
            r'fixture',
            r'seed',
            r'factory',
            r'conftest\.py$',
        ]
        for pattern in fixture_patterns:
            if re.search(pattern, path.name, re.IGNORECASE):
                return True
        return False
    
    def is_mock_indicator(self, finding) -> bool:
        """Check if the finding involves a variable or function that looks like mock data."""
        # Get snippet from either object or dict
        snippet = ""
        if isinstance(finding, dict):
            snippet = finding.get('snippet', '')
        else:
            snippet = getattr(finding, 'snippet', '')
        
        # Check the snippet for mock indicators
        snippet_lower = snippet.lower()
        for pattern in self.mock_patterns_compiled:
            if pattern.search(snippet_lower):
                return True
        
        # Check if variable name contains mock indicators
        # Extract variable names from the message
        message = ""
        if isinstance(finding, dict):
            message = finding.get('message', '')
        else:
            message = getattr(finding, 'message', '')
        
        if 'variable' in message.lower() or 'name' in message.lower():
            # Simple heuristic: if the finding mentions a variable that looks like a mock
            return False  # TODO: Implement more sophisticated detection
        
        return False
    
    def has_suppression_comment(self, finding) -> bool:
        """Check if the code snippet contains a suppression comment."""
        snippet = ""
        if isinstance(finding, dict):
            snippet = finding.get('snippet', '')
        else:
            snippet = getattr(finding, 'snippet', '')
        
        for pattern in self.suppression_patterns_compiled:
            if pattern.search(snippet):
                return True
        return False
    
    def get_confidence_score(self, finding: AuditFinding, file_path: str) -> float:
        """
        Calculate a confidence score (0.0 - 1.0) for a finding.
        Higher score means more likely to be a true positive.
        """
        confidence = 1.0
        
        # Reduce confidence for test files
        if self.is_test_file(file_path):
            confidence *= 0.3
        
        # Reduce confidence for example files
        if self.is_example_file(file_path):
            confidence *= 0.5
        
        # Reduce confidence if suppression comment exists
        if self.has_suppression_comment(finding):
            confidence *= 0.2
        
        # Adjust based on severity
        severity_multipliers = {
            'critical': 1.0,
            'high': 0.9,
            'medium': 0.8,
            'low': 0.7,
            'info': 0.5
        }
        confidence *= severity_multipliers.get(finding.severity.lower(), 0.8)
        
        # Adjust based on category
        if finding.category in ['SQL Injection', 'Command Injection', 'XSS']:
            confidence *= 1.1  # These are usually real issues
        elif finding.category == 'Unknown API':
            confidence *= 0.9  # More prone to false positives
        
        return min(1.0, max(0.0, confidence))
    
    def categorize_findings(self, findings: List[AuditFinding]) -> dict:
        """
        Categorize findings by type for analysis.
        """
        categories = {
            'security': [],
            'performance': [],
            'code_quality': [],
            'silent_failure': [],
            'unknown_api': [],
            'other': []
        }
        
        for finding in findings:
            cat_lower = finding.category.lower()
            if 'security' in cat_lower or any(x in cat_lower for x in ['sql', 'xss', 'injection', 'ssrf', 'crypto', 'secret', 'hardcoded']):
                categories['security'].append(finding)
            elif 'performance' in cat_lower or 'nested' in cat_lower:
                categories['performance'].append(finding)
            elif 'quality' in cat_lower or 'magic' in cat_lower:
                categories['code_quality'].append(finding)
            elif 'silent' in cat_lower or 'except' in cat_lower:
                categories['silent_failure'].append(finding)
            elif 'unknown' in cat_lower or 'api' in cat_lower:
                categories['unknown_api'].append(finding)
            else:
                categories['other'].append(finding)
        
        return categories
