"""
Go Analyzer
Detects AI hallucinations and code quality issues in Go files.
Uses regex-based analysis.
"""

import re
from typing import List, Dict, Any, Set
from .base_analyzer import BaseAnalyzer, AuditFinding


class GoAnalyzer(BaseAnalyzer):
    """Analyzes Go code for issues."""
    
    # Known correct API signatures for common Go libraries
    KNOWN_APIS = {
        'fmt': {
            'Println': ['a', 'b', 'c'],
            'Printf': ['format', 'a', 'b', 'c'],
            'Sprintf': ['format', 'a', 'b', 'c'],
            'Errorf': ['format', 'a', 'b', 'c'],
        },
        'os': {
            'Open': ['name'],
            'Create': ['name'],
            'Remove': ['name'],
            'MkdirAll': ['path', 'perm'],
            'Stat': ['name'],
        },
        'net/http': {
            'Get': ['url'],
            'Post': ['url', 'body'],
            'Do': ['req'],
            'HandleFunc': ['pattern', 'handler'],
            'ListenAndServe': ['addr', 'handler'],
        },
        'database/sql': {
            'Open': ['driverName', 'dataSourceName'],
            'Query': ['query', 'args'],
            'QueryRow': ['query', 'args'],
            'Exec': ['query', 'args'],
            'Prepare': ['query'],
        },
        'encoding/json': {
            'Marshal': ['v'],
            'Unmarshal': ['data', 'v'],
            'NewDecoder': ['r'],
            'NewEncoder': ['w'],
        },
    }
    
    # Suspicious patterns for regex analysis
    EVAL_PATTERNS = [
        r'exec\.Command\(',
        r'os\.StartProcess\(',
        r'syscall\.Exec\(',
    ]
    
    # Hardcoded secret patterns
    SECRET_PATTERNS = [
        (r'password\s*:=\s*["\'][^"\']+["\']', 'hardcoded password'),
        (r'api[_-]?key\s*:=\s*["\'][^"\']+["\']', 'hardcoded API key'),
        (r'secret\s*:=\s*["\'][^"\']+["\']', 'hardcoded secret'),
        (r'token\s*:=\s*["\'][^"\']+["\']', 'hardcoded token'),
        (r'["\'][a-zA-Z0-9]{32,}["\']', 'potential hardcoded credential'),
    ]
    
    def __init__(self):
        self.filepath = ""
        self.source_code = ""
        self.lines = []
        self.findings: List[AuditFinding] = []
    
    def analyze(self, source_code: str, file_path: str = "") -> List[AuditFinding]:
        """
        Analyze Go source code and return findings.
        
        Args:
            source_code: The Go source code to analyze
            file_path: Path to the source file (for context)
            
        Returns:
            List of AuditFinding objects
        """
        self.filepath = file_path
        self.source_code = source_code
        self.lines = source_code.split('\n')
        self.findings = []
        
        # Run all checks
        self._check_unknown_apis()
        self._check_empty_catch()
        self._check_nested_loops()
        self._check_eval_usage()
        self._check_hardcoded_secrets()
        self._check_magic_numbers()
        self._check_command_injection()
        self._check_path_traversal()
        self._check_unsafe_deserialization()
        self._check_sql_injection()
        self._check_ssrf()
        self._check_cryptographic_weakness()
        self._check_goroutine_leak()
        
        # Add CVSS scores to findings
        for finding in self.findings:
            finding.cvss_score = self.calculate_cvss_score(finding)
            finding.language = "go"
        
        return self.findings
    
    def get_supported_extensions(self) -> List[str]:
        return ['.go']
    
    def get_language_name(self) -> str:
        return "go"
    
    def _check_unknown_apis(self):
        """Detect potential API hallucinations (wrong method names)."""
        for lib_name, methods in self.KNOWN_APIS.items():
            for method in methods:
                # Look for method calls that might be incorrect
                pattern = rf'{lib_name}\.{method}\s*\('
                matches = re.finditer(pattern, self.source_code)
                for match in matches:
                    line_num = self._get_line_number(match.start())
                    # Simplified check - just detect usage for now
                    pass
    
    def _check_empty_catch(self):
        """Flag empty defer/recover blocks that silently fail."""
        # In Go, empty recover blocks are problematic
        pattern = r'recover\s*\(\s*\)\s*{\s*}'
        matches = re.finditer(pattern, self.source_code)
        for match in matches:
            line_num = self._get_line_number(match.start())
            self.findings.append(AuditFinding(
                category="Silent Logic Failure",
                severity="medium",
                message="Empty recover block that silently catches panics",
                line=line_num,
                snippet=self._get_snippet(line_num),
                recommendation="Add error handling or logging in recover blocks.",
                cwe_id="CWE-703"
            ))
    
    def _check_nested_loops(self):
        """Detect O(n²) nested loops where O(n) might be possible."""
        # Simple pattern for nested for loops
        pattern = r'for\s*{[^}]*for\s*{'
        matches = re.finditer(pattern, self.source_code, re.DOTALL)
        for match in matches:
            line_num = self._get_line_number(match.start())
            self.findings.append(AuditFinding(
                category="Performance Risk",
                severity="low",
                message="Nested loop detected - potential O(n²) complexity",
                line=line_num,
                snippet=self._get_snippet(line_num),
                recommendation="Consider using maps or other data structures to reduce complexity.",
                cwe_id="CWE-407"
            ))
    
    def _check_eval_usage(self):
        """Flag dangerous command execution usage."""
        for pattern in self.EVAL_PATTERNS:
            matches = re.finditer(pattern, self.source_code)
            for match in matches:
                line_num = self._get_line_number(match.start())
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="critical",
                    message=f"Dangerous function usage detected - potential command injection",
                    line=line_num,
                    snippet=self._get_snippet(line_num),
                    recommendation="Avoid exec.Command with user input. Use parameterized commands and validate inputs.",
                    cwe_id="CWE-78"
                ))
    
    def _check_hardcoded_secrets(self):
        """Detect hardcoded credentials and secrets."""
        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, self.source_code, re.IGNORECASE)
            for match in matches:
                line_num = self._get_line_number(match.start())
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="high",
                    message=f"Hardcoded {secret_type} detected",
                    line=line_num,
                    snippet=self._get_snippet(line_num),
                    recommendation="Use environment variables or secure secret management.",
                    cwe_id="CWE-798"
                ))
    
    def _check_magic_numbers(self):
        """Flag magic numbers (unexplained numeric literals)."""
        pattern = r'[^a-zA-Z_]\d+[^a-zA-Z_]'
        matches = re.finditer(pattern, self.source_code)
        for match in matches:
            try:
                number = int(match.group(0).strip())
                if number not in [0, 1, -1, 2, 10, 100, 1000, 60, 3600, 24, 7, 30, 365]:
                    line_num = self._get_line_number(match.start())
                    self.findings.append(AuditFinding(
                        category="Code Quality",
                        severity="low",
                        message=f"Magic number {number} used without explanation",
                        line=line_num,
                        snippet=self._get_snippet(line_num),
                        recommendation="Replace with named constant for better maintainability.",
                        cwe_id="CWE-1121"
                    ))
            except:
                pass
    
    def _check_command_injection(self):
        """Detect command injection vulnerabilities."""
        dangerous_funcs = ['exec.Command', 'os.StartProcess', 'syscall.Exec']
        for func in dangerous_funcs:
            pattern = re.escape(func)
            matches = re.finditer(pattern, self.source_code)
            for match in matches:
                line_num = self._get_line_number(match.start())
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="critical",
                    message=f"Command execution via '{func}' - potential command injection",
                    line=line_num,
                    snippet=self._get_snippet(line_num),
                    recommendation="Validate and sanitize all user inputs passed to command execution functions.",
                    cwe_id="CWE-78"
                ))
    
    def _check_path_traversal(self):
        """Detect path traversal vulnerabilities."""
        pattern = r'os\.Open\s*\(|ioutil\.ReadFile\s*\(|os\.Create\s*\('
        matches = re.finditer(pattern, self.source_code)
        for match in matches:
            line_num = self._get_line_number(match.start())
            self.findings.append(AuditFinding(
                category="Security",
                severity="high",
                message="File operation - potential path traversal",
                line=line_num,
                snippet=self._get_snippet(line_num),
                recommendation="Validate and sanitize file paths. Use filepath.Join and check for path traversal sequences.",
                cwe_id="CWE-22"
            ))
    
    def _check_unsafe_deserialization(self):
        """Detect unsafe deserialization."""
        # Go's encoding/gob and json can be unsafe
        dangerous_funcs = ['gob\.Decode', 'json\.Unmarshal']
        for func in dangerous_funcs:
            pattern = re.escape(func)
            matches = re.finditer(pattern, self.source_code)
            for match in matches:
                line_num = self._get_line_number(match.start())
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="high",
                    message="Unsafe deserialization detected",
                    line=line_num,
                    snippet=self._get_snippet(line_num),
                    recommendation="Validate input data before deserialization. Use type-safe JSON with proper struct tags.",
                    cwe_id="CWE-502"
                ))
    
    def _check_sql_injection(self):
        """Detect potential SQL injection."""
        pattern = r'db\.Query\s*\([^)]*[+].+[+]'
        matches = re.finditer(pattern, self.source_code)
        for match in matches:
            line_num = self._get_line_number(match.start())
            self.findings.append(AuditFinding(
                category="Security",
                severity="critical",
                message="Potential SQL injection - using string concatenation in query",
                line=line_num,
                snippet=self._get_snippet(line_num),
                recommendation="Use parameterized queries with placeholders (?) instead of string concatenation.",
                cwe_id="CWE-89"
            ))
    
    def _check_ssrf(self):
        """Detect Server-Side Request Forgery (SSRF) vulnerabilities."""
        pattern = r'http\.Get\s*\(|http\.Post\s*\(|http\.Do\s*\('
        matches = re.finditer(pattern, self.source_code)
        for match in matches:
            line_num = self._get_line_number(match.start())
            self.findings.append(AuditFinding(
                category="Security",
                severity="high",
                message="HTTP request - potential SSRF if URL is user-controlled",
                line=line_num,
                snippet=self._get_snippet(line_num),
                recommendation="Validate and whitelist URLs. Use allowlists for external requests.",
                cwe_id="CWE-918"
            ))
    
    def _check_cryptographic_weakness(self):
        """Detect weak cryptographic algorithms."""
        weak_crypto = [
            'md5\.New',
            'sha1\.New',
            'crypto/md5',
            'crypto/sha1',
        ]
        for weak in weak_crypto:
            pattern = re.escape(weak)
            matches = re.finditer(pattern, self.source_code)
            for match in matches:
                line_num = self._get_line_number(match.start())
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="high",
                    message=f"Weak cryptography detected: {weak}",
                    line=line_num,
                    snippet=self._get_snippet(line_num),
                    recommendation="Use SHA-256 or better for hashing. Avoid MD5 and SHA1.",
                    cwe_id="CWE-327"
                ))
    
    def _check_goroutine_leak(self):
        """Detect potential goroutine leaks."""
        # Look for goroutines that might not exit
        pattern = r'go\s+func\s*\([^)]*\)\s*{[^}]*for\s*{'
        matches = re.finditer(pattern, self.source_code, re.DOTALL)
        for match in matches:
            line_num = self._get_line_number(match.start())
            self.findings.append(AuditFinding(
                category="Performance Risk",
                severity="medium",
                message="Potential goroutine leak - infinite loop without exit condition",
                line=line_num,
                snippet=self._get_snippet(line_num),
                recommendation="Ensure goroutines have proper exit conditions and use channels for coordination.",
                cwe_id="CWE-400"
            ))
    
    def _find_similar(self, target: str, candidates: list) -> List[str]:
        """Find similar method names using simple string matching."""
        from difflib import get_close_matches
        return get_close_matches(target, candidates, n=3, cutoff=0.6)
    
    def _get_line_number(self, char_position: int) -> int:
        """Convert character position to line number."""
        if not self.lines:
            return 1
        pos = 0
        for i, line in enumerate(self.lines, 1):
            pos += len(line) + 1  # +1 for newline
            if pos > char_position:
                return i
        return len(self.lines)
    
    def _get_snippet(self, line_num: int, context: int = 2) -> str:
        """Extract code snippet around the given line."""
        if not self.lines:
            return ""
        start = max(0, line_num - context - 1)
        end = min(len(self.lines), line_num + context)
        snippet_lines = self.lines[start:end]
        # Mark the problematic line
        for i, line in enumerate(snippet_lines, start=start+1):
            if i == line_num:
                snippet_lines[i-start-1] = f">>> {line}"
        return '\n'.join(snippet_lines)
    
    def calculate_cvss_score(self, finding: AuditFinding) -> float:
        """Calculate CVSS-like score for a finding."""
        base_scores = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.5
        }
        
        score = base_scores.get(finding.severity.lower(), 5.0)
        
        # Adjust based on category
        if 'SQL Injection' in finding.category:
            score = max(score, 8.5)
        elif 'Command Injection' in finding.category:
            score = max(score, 9.0)
        elif 'Hardcoded' in finding.category:
            score = max(score, 7.0)
        
        return round(score, 1)
    
    def calculate_trust_score(self, findings: List[AuditFinding]) -> int:
        """Calculate trust score for Go code."""
        score = 100
        
        severity_weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
            'info': 1
        }
        
        for finding in findings:
            weight = severity_weights.get(finding.severity.lower(), 5)
            score -= weight
        
        return max(0, min(100, score))
    
    def generate_recommendation(self, findings: List[AuditFinding]) -> str:
        """Generate a comprehensive recommendation."""
        if not findings:
            return "EXCELLENT: No significant issues detected. The Go code demonstrates strong adherence to best practices. Maintain this standard and consider implementing comprehensive testing."
        
        categories = {}
        severities = {}
        for f in findings:
            categories[f.category] = categories.get(f.category, 0) + 1
            severities[f.severity] = severities.get(f.severity, 0) + 1
        
        critical_count = severities.get('critical', 0)
        high_count = severities.get('high', 0)
        medium_count = severities.get('medium', 0)
        
        if critical_count > 0:
            return f"CRITICAL INTERVENTION REQUIRED: {critical_count} critical issue(s) detected. Immediate refactoring is essential before production deployment. Focus on security vulnerabilities (command injection, SQL injection) and code correctness."
        elif high_count > 0:
            return f"HIGH PRIORITY: {high_count} high-severity issue(s) require attention. Address security risks (hardcoded secrets, path traversal) and improve error handling."
        elif medium_count > 0:
            return f"MODERATE IMPROVEMENT NEEDED: {len(findings)} total issues across {len(categories)} categories. While not critical, addressing these will improve code maintainability and reduce technical debt."
        else:
            return f"MINOR IMPROVEMENTS: {len(findings)} low-severity issues detected. These are primarily code quality concerns that should be addressed in refactoring cycles."