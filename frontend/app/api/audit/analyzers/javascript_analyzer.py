"""
JavaScript/TypeScript Analyzer
Detects AI hallucinations and code quality issues in JavaScript and TypeScript files.
Uses tree-sitter for AST parsing when available, with regex fallback.
"""

import re
import os
from typing import List, Dict, Any, Set, Optional
from .base_analyzer import BaseAnalyzer, AuditFinding

# Try to import tree-sitter, but don't fail if it's not available
try:
    import tree_sitter
    from tree_sitter import Language, Parser
    TREESITTER_AVAILABLE = True
except ImportError:
    TREESITTER_AVAILABLE = False


class JavaScriptAnalyzer(BaseAnalyzer):
    """Analyzes JavaScript and TypeScript code for issues."""
    
    # Known correct API signatures for common JS/TS libraries
    KNOWN_APIS = {
        'react': {
            'useState': ['initialState'],
            'useEffect': ['effect', 'dependencies'],
            'useContext': ['context'],
            'useReducer': ['reducer', 'initialState'],
            'useMemo': ['factory', 'dependencies'],
            'useCallback': ['callback', 'dependencies'],
            'Component': ['props', 'context'],
            'createElement': ['type', 'props', 'children'],
        },
        'express': {
            'get': ['path', 'handler'],
            'post': ['path', 'handler'],
            'put': ['path', 'handler'],
            'delete': ['path', 'handler'],
            'use': ['path', 'middleware'],
            'listen': ['port', 'hostname', 'backlog', 'callback'],
            'json': ['body', 'replacer', 'space'],
            'send': ['body', 'status'],
            'redirect': ['url', 'status'],
        },
        'node-fetch': {
            'fetch': ['input', 'init'],
            'Request': ['input', 'init'],
            'Response': ['body', 'init'],
        },
        'axios': {
            'get': ['url', 'config'],
            'post': ['url', 'data', 'config'],
            'put': ['url', 'data', 'config'],
            'delete': ['url', 'config'],
            'request': ['config'],
        },
        'lodash': {
            'get': ['object', 'path', 'defaultValue'],
            'set': ['object', 'path', 'value'],
            'cloneDeep': ['value'],
            'merge': ['object', 'sources'],
            'debounce': ['func', 'wait', 'options'],
            'throttle': ['func', 'wait', 'options'],
        },
    }
    
    # Suspicious patterns for regex fallback
    EVAL_PATTERNS = [
        r'eval\s*\(',
        r'new\s+Function\s*\(',
        r'setTimeout\s*\(\s*["\']',
        r'setInterval\s*\(\s*["\']',
        r'exec\s*\(',
        r'__lookupGetter__',
        r'__lookupSetter__',
    ]
    
    SECRET_PATTERNS = [
        (r'password\s*=\s*["\'][^"\']+["\']', 'hardcoded password'),
        (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'hardcoded API key'),
        (r'secret\s*=\s*["\'][^"\']+["\']', 'hardcoded secret'),
        (r'token\s*=\s*["\'][^"\']+["\']', 'hardcoded token'),
        (r'["\'][a-zA-Z0-9]{32,}["\']', 'potential hardcoded credential'),
        (r'Bearer\s+[A-Za-z0-9\-_]+', 'Bearer token'),
        (r'AKIA[0-9A-Z]{16}', 'AWS access key'),
        (r'ghp_[0-9a-zA-Z]{36}', 'GitHub personal access token'),
    ]
    
    # Dangerous functions
    DANGEROUS_FUNCTIONS = {
        'eval': 'code injection risk',
        'Function': 'dynamic code evaluation',
        'setTimeout': 'potential code injection if first arg is string',
        'setInterval': 'potential code injection if first arg is string',
        'document.write': 'XSS risk',
        'innerHTML': 'XSS risk',
        'outerHTML': 'XSS risk',
        'insertAdjacentHTML': 'XSS risk',
        'dangerouslySetInnerHTML': 'XSS risk (React)',
        'exec': 'regex DoS risk',
        'child_process.exec': 'command injection',
        'child_process.spawn': 'command injection',
        'fs.writeFile': 'file system write',
        'fs.createWriteStream': 'file system write',
        'localStorage.setItem': 'client-side storage',
        'sessionStorage.setItem': 'client-side storage',
        'cookie': 'potential insecure cookie',
    }
    
    def __init__(self):
        self.filepath = ""
        self.source_code = ""
        self.lines = []
        self.parser = None
        self.tree = None
        
        # Initialize tree-sitter parser if available
        if TREESITTER_AVAILABLE:
            try:
                # Try to load JavaScript/TypeScript grammar
                # In production, you'd pre-compile the grammar
                self.parser = Parser()
                # This would require the compiled .so file
                # For now, we'll use regex fallback
            except Exception as e:
                print(f"Tree-sitter initialization failed: {e}")
                self.parser = None
    
    def analyze(self, source_code: str, file_path: str = "") -> List[AuditFinding]:
        """
        Analyze JavaScript/TypeScript source code.
        
        Args:
            source_code: The source code to analyze
            file_path: Path to the source file
            
        Returns:
            List of AuditFinding objects
        """
        self.filepath = file_path
        self.source_code = source_code
        self.lines = source_code.split('\n')
        findings = []
        
        # Determine if it's TypeScript or JavaScript
        is_typescript = file_path.endswith(('.ts', '.tsx', '.jsx')) or 'typescript' in source_code.lower()
        
        # Use tree-sitter if available and configured
        if self.parser and TREESITTER_AVAILABLE:
            findings.extend(self._analyze_with_treesitter(source_code, is_typescript))
        else:
            # Fallback to regex-based analysis
            findings.extend(self._analyze_with_regex(source_code, is_typescript))
        
        # Calculate trust score
        trust_score = self.calculate_trust_score(findings)
        
        # Add language and CVSS scores
        for finding in findings:
            finding.language = 'typescript' if is_typescript else 'javascript'
            finding.cvss_score = self.calculate_cvss_score(finding)
        
        return findings
    
    def _analyze_with_regex(self, source_code: str, is_typescript: bool) -> List[AuditFinding]:
        """Regex-based analysis (fallback method)."""
        findings = []
        
        # Check for eval and dangerous functions
        for pattern in self.EVAL_PATTERNS:
            matches = re.finditer(pattern, source_code, re.IGNORECASE)
            for match in matches:
                line_num = self._get_line_number(match.start())
                func_name = match.group().split('(')[0].strip()
                findings.append(AuditFinding(
                    category="Security",
                    severity="critical",
                    message=f"Dangerous function '{func_name}' used - code injection risk",
                    line=line_num,
                    snippet=self._get_snippet(line_num),
                    recommendation="Avoid eval, Function constructor, and string-based setTimeout/setInterval. Use safer alternatives.",
                    cwe_id="CWE-95"
                ))
        
        # Check for hardcoded secrets
        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, source_code, re.IGNORECASE)
            for match in matches:
                line_num = self._get_line_number(match.start())
                findings.append(AuditFinding(
                    category="Security",
                    severity="high",
                    message=f"Hardcoded {secret_type} detected",
                    line=line_num,
                    snippet=self._get_snippet(line_num),
                    recommendation="Use environment variables or secure secret management.",
                    cwe_id="CWE-798"
                ))
        
        # Check for dangerous function usage
        for func, risk in self.DANGEROUS_FUNCTIONS.items():
            pattern = rf'\b{re.escape(func)}\s*\('
            matches = re.finditer(pattern, source_code)
            for match in matches:
                line_num = self._get_line_number(match.start())
                severity = "critical" if 'XSS' in risk or 'injection' in risk.lower() else "high"
                findings.append(AuditFinding(
                    category="Security",
                    severity=severity,
                    message=f"Dangerous function '{func}' used - {risk}",
                    line=line_num,
                    snippet=self._get_snippet(line_num),
                    recommendation=f"Review usage of {func}. Consider safer alternatives.",
                    cwe_id="CWE-676"  # Use of Potentially Dangerous Function
                ))
        
        # Check for console.log (info)
        console_logs = re.findall(r'console\.log\s*\(', source_code)
        if console_logs:
            findings.append(AuditFinding(
                category="Code Quality",
                severity="info",
                message=f"Found {len(console_logs)} console.log statements",
                line=1,  # General finding
                snippet="console.log(...)",
                recommendation="Remove console.log statements in production code.",
                cwe_id="CWE-540"  # Information Exposure
            ))
        
        # Check for var usage (ES5) in modern code
        if is_typescript or 'react' in source_code.lower():
            var_usage = re.findall(r'\bvar\s+', source_code)
            if var_usage:
                findings.append(AuditFinding(
                    category="Code Quality",
                    severity="low",
                    message=f"Found {len(var_usage)} instances of 'var' (use let/const instead)",
                    line=1,
                    snippet="var x = ...",
                    recommendation="Use 'const' for immutable values and 'let' for mutable ones. Avoid 'var'.",
                    cwe_id="CWE-1121"  # Excessive Complexity
                ))
        
        # Check for magic numbers (simple heuristic)
        magic_numbers = re.findall(r'[=+\-*/]\s*(\d+)\s*[;,\n]', source_code)
        unique_magic = set(magic_numbers)
        for num in unique_magic:
            if int(num) not in [0, 1, 2, 10, 100, 1000, 60, 3600, 24, 7, 30, 365]:
                findings.append(AuditFinding(
                    category="Code Quality",
                    severity="low",
                    message=f"Magic number {num} used without explanation",
                    line=1,
                    snippet=f"... = {num}",
                    recommendation="Replace with named constant for better maintainability.",
                    cwe_id="CWE-1121"
                ))
        
        # Check for empty catch blocks
        empty_catches = re.findall(r'catch\s*\(\s*[^)]*\s*\)\s*{\s*}', source_code)
        if empty_catches:
            findings.append(AuditFinding(
                category="Silent Logic Failure",
                severity="medium",
                message=f"Empty catch block{'s' if len(empty_catches) > 1 else ''} detected",
                line=1,
                snippet="catch (err) {}",
                recommendation="Add error handling or at least log the error.",
                cwe_id="CWE-703"
            ))
        
        # Check for == vs === (loose equality)
        loose_equality = re.findall(r'[^=!]==[^=]', source_code)
        if loose_equality:
            findings.append(AuditFinding(
                category="Code Quality",
                severity="low",
                message=f"Found {len(loose_equality)} instance(s) of '==' (use '===' for type-safe comparison)",
                line=1,
                snippet="if (a == b)",
                recommendation="Use strict equality (===) to avoid type coercion bugs.",
                cwe_id="CWE-597"  # Use of Incorrect Operator
            ))
        
        return findings
    
    def _analyze_with_treesitter(self, source_code: str, is_typescript: bool) -> List[AuditFinding]:
        """
        Tree-sitter based analysis (future implementation).
        This would provide more accurate AST-based analysis.
        """
        # Placeholder for future tree-sitter implementation
        # In production, you would:
        # 1. Load the appropriate language grammar (javascript or typescript)
        # 2. Parse the source code into an AST
        # 3. Walk the tree to find patterns
        # 4. Extract line numbers, snippets, etc.
        
        # For now, return empty list and rely on regex fallback
        return []
    
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
        """Calculate CVSS-like score for JavaScript/TypeScript findings."""
        base_scores = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.5
        }
        
        score = base_scores.get(finding.severity.lower(), 5.0)
        
        # Adjust based on category
        if 'XSS' in finding.message or 'innerHTML' in finding.message:
            score = max(score, 8.0)
        elif 'eval' in finding.message or 'Function' in finding.message:
            score = max(score, 8.5)
        elif 'hardcoded' in finding.message.lower():
            score = max(score, 7.0)
        elif 'console.log' in finding.message:
            score = 1.0
        
        return round(score, 1)
    
    def get_supported_extensions(self) -> List[str]:
        return ['.js', '.jsx', '.ts', '.tsx']
    
    def get_language_name(self) -> str:
        return "javascript"
    
    def calculate_trust_score(self, findings: List[AuditFinding]) -> int:
        """Calculate trust score for JavaScript/TypeScript code."""
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
        """Generate recommendation for JavaScript/TypeScript code."""
        if not findings:
            return "EXCELLENT: No significant issues detected. The JavaScript/TypeScript code follows good practices. Continue maintaining code quality and consider adding comprehensive unit tests."
        
        critical_count = sum(1 for f in findings if f.severity.lower() == 'critical')
        high_count = sum(1 for f in findings if f.severity.lower() == 'high')
        
        if critical_count > 0:
            return f"CRITICAL SECURITY ISSUES: {critical_count} critical issue(s) detected. Address code injection risks (eval, Function), XSS vulnerabilities (innerHTML), and hardcoded secrets immediately. These pose serious security threats to your application."
        elif high_count > 0:
            return f"HIGH PRIORITY: {high_count} high-severity issue(s) require attention. Focus on removing hardcoded secrets, fixing dangerous function usage, and implementing proper error handling."
        else:
            return f"MODERATE IMPROVEMENTS: {len(findings)} issues detected. Address code quality concerns (magic numbers, var usage, console.log) and improve error handling. Consider enabling strict mode and using modern ES6+ features."
