"""
Python Code Analyzer
Detects AI hallucinations and code quality issues in Python files.
"""

import ast
import re
from pathlib import Path
from typing import List, Dict, Any, Set
from .base_analyzer import BaseAnalyzer, AuditFinding


class PythonAnalyzer(BaseAnalyzer):
    """Analyzes Python code for AI hallucinations and security issues."""
    
    # Known correct API signatures (common libraries)
    KNOWN_APIS = {
        'pandas': {
            'read_csv': ['filepath_or_buffer', 'sep', 'delimiter', 'header', 'names', 'index_col'],
            'read_excel': ['io', 'sheet_name', 'header', 'names', 'index_col', 'usecols'],
            'read_json': ['path_or_buf', 'orient', 'typ', 'dtype', 'convert_axes'],
            'DataFrame': ['data', 'index', 'columns', 'dtype', 'copy'],
            'to_csv': ['path_or_buf', 'sep', 'na_rep', 'float_format', 'columns', 'header', 'index'],
            'to_json': ['path_or_buf', 'orient', 'date_format', 'double_precision', 'force_ascii'],
        },
        'numpy': {
            'array': ['object', 'dtype', 'copy', 'order', 'subok', 'ndmin'],
            'zeros': ['shape', 'dtype', 'order'],
            'ones': ['shape', 'dtype', 'order'],
            'linspace': ['start', 'stop', 'num', 'endpoint', 'retstep', 'dtype', 'axis'],
            'arange': ['start', 'stop', 'step', 'dtype'],
            'random': ['rand', 'randint', 'randn', 'choice'],
        },
        'os': {
            'path': ['join', 'exists', 'isfile', 'isdir', 'getsize', 'getmtime'],
            'environ': ['get', 'setdefault', 'items', 'keys', 'values'],
            'listdir': ['path'],
            'walk': ['top', 'topdown', 'onerror', 'followlinks'],
        },
        'json': {
            'load': ['fp', 'cls', 'object_hook', 'parse_float', 'parse_int', 'parse_constant'],
            'loads': ['s', 'encoding', 'cls', 'object_hook', 'parse_float', 'parse_int'],
            'dump': ['obj', 'fp', 'skipkeys', 'ensure_ascii', 'check_circular', 'allow_nan'],
            'dumps': ['obj', 'skipkeys', 'ensure_ascii', 'check_circular', 'allow_nan', 'cls'],
        },
        'requests': {
            'get': ['url', 'params', 'kwargs'],
            'post': ['url', 'data', 'json', 'kwargs'],
            'put': ['url', 'data', 'kwargs'],
            'delete': ['url', 'kwargs'],
            'head': ['url', 'kwargs'],
            'request': ['method', 'url', 'kwargs'],
        },
        'flask': {
            'request': ['method', 'url', 'values', 'json', 'args', 'form', 'files'],
            'jsonify': ['*args', '**kwargs'],
            'redirect': ['location', 'code'],
            'url_for': ['endpoint', 'values'],
            'abort': ['code'],
        },
        'django': {
            'HttpResponse': ['content', 'content_type', 'status'],
            'render': ['request', 'template_name', 'context'],
            'redirect': ['to', 'permanent'],
            'get_object_or_404': ['model', 'kwargs'],
        },
    }
    
    # Suspicious patterns
    EVAL_PATTERNS = [
        r'eval\s*\(',
        r'exec\s*\(',
        r'__import__\s*\(',
        r'compile\s*\(',
    ]
    
    # Hardcoded secret patterns
    SECRET_PATTERNS = [
        (r'password\s*=\s*["\'][^"\']+["\']', 'hardcoded password'),
        (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'hardcoded API key'),
        (r'secret\s*=\s*["\'][^"\']+["\']', 'hardcoded secret'),
        (r'token\s*=\s*["\'][^"\']+["\']', 'hardcoded token'),
        (r'["\'][a-zA-Z0-9]{32,}["\']', 'potential hardcoded credential'),
        (r'AKIA[0-9A-Z]{16}', 'AWS access key'),
        (r'ghp_[0-9a-zA-Z]{36}', 'GitHub personal access token'),
        (r'Bearer\s+[A-Za-z0-9\-_]+', 'Bearer token'),
    ]
    
    def __init__(self, filepath: str = ""):
        self.filepath = filepath
        self.tree = None
        self.source_code = ""
        self.findings: List[AuditFinding] = []
        self.trust_score = 100
        self.imported_modules: Dict[str, Set[str]] = {}
        self.lines = []
    
    def analyze(self, source_code: str, file_path: str = "") -> List[AuditFinding]:
        """
        Analyze Python source code and return findings.
        
        Args:
            source_code: The Python source code to analyze
            file_path: Path to the source file (for context)
            
        Returns:
            List of AuditFinding objects
        """
        self.filepath = file_path
        self.source_code = source_code
        self.lines = source_code.split('\n')
        self.findings = []
        
        try:
            self.tree = ast.parse(source_code)
        except SyntaxError as e:
            self.findings.append(AuditFinding(
                category="System",
                severity="critical",
                message=f"Syntax error in file: {str(e)}",
                line=e.lineno or 1,
                column=e.offset or 1,
                snippet=self._get_snippet(e.lineno or 1),
                recommendation="Fix the syntax error before proceeding.",
                language="python"
            ))
            return self.findings
        
        # First pass: collect all imports
        self._collect_imports()
        
        # Run all checks
        for node in ast.walk(self.tree):
            self._check_unknown_apis(node)
            self._check_empty_except(node)
            self._check_bare_except(node)
            self._check_nested_loops(node)
            self._check_eval_usage(node)
            self._check_hardcoded_secrets(node)
            self._check_magic_numbers(node)
            self._check_command_injection(node)
            self._check_path_traversal(node)
            self._check_unsafe_deserialization(node)
            self._check_sql_injection(node)
            self._check_ssrf(node)
            self._check_cryptographic_weakness(node)
        
        # Calculate trust score
        self._calculate_trust_score()
        
        # Add CVSS scores to findings
        for finding in self.findings:
            finding.cvss_score = self.calculate_cvss_score(finding)
            finding.language = "python"
        
        return self.findings
    
    def get_supported_extensions(self) -> List[str]:
        return ['.py']
    
    def get_language_name(self) -> str:
        return "python"
    
    def _collect_imports(self):
        """Collect all import statements to map aliases to real module names."""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split('.')[0]
                    if module not in self.imported_modules:
                        self.imported_modules[module] = set()
                    alias_name = alias.asname if alias.asname else module
                    self.imported_modules[module].add(alias_name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module = node.module.split('.')[0]
                    if module not in self.imported_modules:
                        self.imported_modules[module] = set()
                    for alias in node.names:
                        alias_name = alias.asname if alias.asname else alias.name
                        self.imported_modules[module].add(alias_name)
    
    def _check_unknown_apis(self, node: ast.AST):
        """Detect potential API hallucinations (wrong method names)."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            if func_name and '.' in func_name:
                parts = func_name.split('.')
                object_name = parts[0]
                method_name = parts[-1]
                
                # Check if this object corresponds to a known library
                for lib_name, methods in self.KNOWN_APIS.items():
                    if (object_name == lib_name or
                        any(alias == object_name for alias in self.imported_modules.get(lib_name, set()))):
                        if method_name not in methods:
                            similar = self._find_similar(method_name, methods.keys())
                            if similar:
                                self.findings.append(AuditFinding(
                                    category="Unknown API",
                                    severity="high",
                                    message=f"Potentially hallucinated method '{method_name}' in {lib_name}. Did you mean: {', '.join(similar)}?",
                                    line=node.lineno,
                                    snippet=self._get_snippet(node.lineno),
                                    recommendation=f"Verify the {lib_name} API documentation for correct method names.",
                                    cwe_id="CWE-1104"  # Use of Dangerous Function
                                ))
    
    def _check_empty_except(self, node: ast.AST):
        """Flag empty except blocks that silently fail."""
        if isinstance(node, ast.ExceptHandler):
            has_only_pass = (
                not node.body or 
                all(isinstance(stmt, (ast.Pass, ast.Expr)) and 
                    (not isinstance(stmt, ast.Expr) or 
                     isinstance(stmt.value, ast.Constant) and stmt.value.value is ...) 
                    for stmt in node.body)
            )
            if has_only_pass:
                self.findings.append(AuditFinding(
                    category="Silent Logic Failure",
                    severity="medium",
                    message="Empty except block that silently catches all exceptions",
                    line=node.lineno,
                    snippet=self._get_snippet(node.lineno),
                    recommendation="Add specific exception handling or at least log the error.",
                    cwe_id="CWE-703"  # Improper Check or Handling of Exceptional Conditions
                ))
    
    def _check_bare_except(self, node: ast.AST):
        """Flag bare except: clauses (bad practice)."""
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            self.findings.append(AuditFinding(
                category="Silent Logic Failure",
                severity="medium",
                message="Bare 'except:' catches all exceptions including SystemExit and KeyboardInterrupt",
                line=node.lineno,
                snippet=self._get_snippet(node.lineno),
                recommendation="Use 'except Exception:' or catch specific exceptions.",
                cwe_id="CWE-703"
            ))
    
    def _check_nested_loops(self, node: ast.AST):
        """Detect O(n²) nested loops where O(n) might be possible."""
        if isinstance(node, (ast.For, ast.While)):
            for child in ast.walk(node):
                if isinstance(child, (ast.For, ast.While)) and child is not node:
                    self.findings.append(AuditFinding(
                        category="Performance Risk",
                        severity="low",
                        message="Nested loop detected - potential O(n²) complexity",
                        line=node.lineno,
                        snippet=self._get_snippet(node.lineno),
                        recommendation="Consider using dictionaries, sets, or list comprehensions to reduce complexity.",
                        cwe_id="CWE-407"  # Inefficient Algorithmic Complexity
                    ))
                    break
    
    def _check_eval_usage(self, node: ast.AST):
        """Flag dangerous eval() usage."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            if func_name in ['eval', 'exec', '__import__', 'compile']:
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="critical",
                    message=f"Dangerous function '{func_name}' used - code injection risk",
                    line=node.lineno,
                    snippet=self._get_snippet(node.lineno),
                    recommendation="Avoid eval/exec. Use safer alternatives like ast.literal_eval() or specific APIs.",
                    cwe_id="CWE-95"  # Improper Neutralization of Directives in Dynamically Evaluated Code
                ))
    
    def _check_hardcoded_secrets(self, node: ast.AST):
        """Detect hardcoded credentials and secrets."""
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    for pattern, secret_type in self.SECRET_PATTERNS:
                        if re.search(pattern, f"{var_name} = ", re.IGNORECASE):
                            self.findings.append(AuditFinding(
                                category="Security",
                                severity="high",
                                message=f"Hardcoded {secret_type} detected",
                                line=node.lineno,
                                snippet=self._get_snippet(node.lineno),
                                recommendation="Use environment variables or secure secret management.",
                                cwe_id="CWE-798"  # Use of Hard-coded Credentials
                            ))
                            break
    
    def _check_magic_numbers(self, node: ast.AST):
        """Flag magic numbers (unexplained numeric literals)."""
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            if node.value not in [0, 1, -1, 2, 10, 100, 1000, 60, 3600, 24, 7, 30, 365]:
                parent = self._find_parent(node)
                if isinstance(parent, ast.Assign):
                    for target in parent.targets:
                        if isinstance(target, ast.Name) and target.id.isupper():
                            return
                else:
                    self.findings.append(AuditFinding(
                        category="Code Quality",
                        severity="low",
                        message=f"Magic number {node.value} used without explanation",
                        line=node.lineno,
                        snippet=self._get_snippet(node.lineno),
                        recommendation="Replace with named constant for better maintainability.",
                        cwe_id="CWE-1121"  # Excessive Comment Density / Magic Numbers
                    ))
    
    def _check_command_injection(self, node: ast.AST):
        """Detect command injection vulnerabilities."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            dangerous_funcs = ['os.system', 'os.popen', 'subprocess.run', 'subprocess.call', 
                             'subprocess.Popen', 'subprocess.check_output']
            if func_name in dangerous_funcs:
                # Check if any argument contains user input (simple heuristic)
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="critical",
                    message=f"Command execution via '{func_name}' - potential command injection",
                    line=node.lineno,
                    snippet=self._get_snippet(node.lineno),
                    recommendation="Use subprocess with shell=False and pass arguments as a list. Validate and sanitize all user inputs.",
                    cwe_id="CWE-78"  # OS Command Injection
                ))
    
    def _check_path_traversal(self, node: ast.AST):
        """Detect path traversal vulnerabilities."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            dangerous_funcs = ['open', 'os.open', 'pathlib.Path.open']
            if func_name in dangerous_funcs:
                # Check if the first argument is from user input (simple heuristic)
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="high",
                    message=f"File operation '{func_name}' - potential path traversal",
                    line=node.lineno,
                    snippet=self._get_snippet(node.lineno),
                    recommendation="Validate and sanitize file paths. Use os.path.abspath() and check the result is within expected directory.",
                    cwe_id="CWE-22"  # Path Traversal
                ))
    
    def _check_unsafe_deserialization(self, node: ast.AST):
        """Detect unsafe deserialization."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            dangerous_funcs = ['pickle.load', 'pickle.loads', 'yaml.load', 'yaml.unsafe_load']
            if func_name in dangerous_funcs:
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="high",
                    message=f"Unsafe deserialization via '{func_name}'",
                    line=node.lineno,
                    snippet=self._get_snippet(node.lineno),
                    recommendation="Use pickle.loads only with trusted data. For YAML, use yaml.safe_load(). Consider using JSON for untrusted data.",
                    cwe_id="CWE-502"  # Deserialization of Untrusted Data
                ))
    
    def _check_sql_injection(self, node: ast.AST):
        """Detect potential SQL injection."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            # Check for common SQL execution functions
            sql_funcs = ['execute', 'executemany', 'cursor.execute']
            if any(func_name.endswith(f) for f in sql_funcs):
                # Check if using string formatting or concatenation
                if node.args and isinstance(node.args[0], ast.BinOp):
                    self.findings.append(AuditFinding(
                        category="Security",
                        severity="critical",
                        message="Potential SQL injection - using string formatting/concatenation in query",
                        line=node.lineno,
                        snippet=self._get_snippet(node.lineno),
                        recommendation="Use parameterized queries with placeholders (?, %s, etc.) instead of string formatting.",
                        cwe_id="CWE-89"  # SQL Injection
                    ))
    
    def _check_ssrf(self, node: ast.AST):
        """Detect Server-Side Request Forgery (SSRF) vulnerabilities."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            http_funcs = ['requests.get', 'requests.post', 'requests.request', 
                         'urllib.request.urlopen', 'http.client.HTTPConnection']
            if func_name in http_funcs:
                # Check if URL comes from user input (simple heuristic)
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="high",
                    message=f"HTTP request '{func_name}' - potential SSRF if URL is user-controlled",
                    line=node.lineno,
                    snippet=self._get_snippet(node.lineno),
                    recommendation="Validate and whitelist URLs. Use allowlists for external requests. Consider using a safe URL parser.",
                    cwe_id="CWE-918"  # Server-Side Request Forgery
                ))
    
    def _check_cryptographic_weakness(self, node: ast.AST):
        """Detect weak cryptographic algorithms."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            weak_crypto = [
                'hashlib.md5', 'hashlib.sha1', 'Crypto.Hash.MD5', 'Crypto.Hash.SHA1',
                'Crypto.Cipher.DES', 'Crypto.Cipher.RC4', 'cryptography.hazmat.primitives.ciphers.algorithms.ARC4'
            ]
            if func_name in weak_crypto:
                self.findings.append(AuditFinding(
                    category="Security",
                    severity="high",
                    message=f"Weak cryptography '{func_name}' detected",
                    line=node.lineno,
                    snippet=self._get_snippet(node.lineno),
                    recommendation="Use SHA-256 or better for hashing. Use AES-GCM for encryption. Avoid MD5, SHA1, DES, RC4.",
                    cwe_id="CWE-327"  # Use of a Broken or Risky Cryptographic Algorithm
                ))
    
    def _find_similar(self, target: str, candidates: list) -> List[str]:
        """Find similar method names using Levenshtein distance."""
        from difflib import get_close_matches
        return get_close_matches(target, candidates, n=3, cutoff=0.6)
    
    def _get_call_name(self, func: ast.AST) -> str:
        """Extract the full function name from a Call node."""
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            value_name = self._get_call_name(func.value)
            if value_name:
                return f"{value_name}.{func.attr}"
        return ""
    
    def _find_parent(self, node: ast.AST) -> ast.AST:
        """Find parent node in the tree (simplified)."""
        # In a full implementation, we'd track parent relationships during traversal
        return None
    
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
    
    def _calculate_trust_score(self):
        """Calculate final trust score starting from 100."""
        score = 100
        
        severity_weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
            'info': 1
        }
        
        for finding in self.findings:
            weight = severity_weights.get(finding.severity.lower(), 5)
            score -= weight
        
        self.trust_score = max(0, min(100, score))
    
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
        if finding.category == 'SQL Injection':
            score = max(score, 8.5)
        elif finding.category == 'Command Injection':
            score = max(score, 9.0)
        elif finding.category == 'Hardcoded Secret':
            score = max(score, 7.0)
        elif finding.category == 'Unknown API':
            score = max(score, 6.0)
        
        return round(score, 1)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate the final JSON report."""
        recommendation = self._generate_recommendation()
        
        return {
            "TrustScore": self.trust_score,
            "Findings": [f.to_dict() for f in self.findings],
            "PhD_Level_Recommendation": recommendation,
            "AuditMetadata": {
                "file": self.filepath,
                "audit_date": datetime.now().isoformat(),
                "engine_version": "2.0.0",
                "total_findings": len(self.findings),
                "language": "python"
            }
        }
    
    def _generate_recommendation(self) -> str:
        """Generate a comprehensive PhD-level recommendation."""
        if not self.findings:
            return "EXCELLENT: No significant issues detected. The code demonstrates strong adherence to best practices. Maintain this standard and consider implementing automated testing for continuous quality assurance."
        
        categories = {}
        severities = {}
        for f in self.findings:
            categories[f.category] = categories.get(f.category, 0) + 1
            severities[f.severity] = severities.get(f.severity, 0) + 1
        
        critical_count = severities.get('critical', 0)
        high_count = severities.get('high', 0)
        medium_count = severities.get('medium', 0)
        
        if critical_count > 0:
            return f"CRITICAL INTERVENTION REQUIRED: {critical_count} critical issue(s) detected. Immediate refactoring is essential before production deployment. Focus on security vulnerabilities (eval, command injection, SQL injection) and API correctness. The current code exhibits patterns consistent with AI hallucination artifacts."
        elif high_count > 0:
            return f"HIGH PRIORITY: {high_count} high-severity issue(s) require attention. Address security risks (hardcoded secrets, SSRF, path traversal) and API misuses. Consider implementing static analysis in CI/CD pipeline to prevent regressions."
        elif medium_count > 0:
            return f"MODERATE IMPROVEMENT NEEDED: {len(self.findings)} total issues across {len(categories)} categories. While not critical, addressing these will improve code maintainability and reduce technical debt. Focus on error handling, performance optimization, and code quality."
        else:
            return f"MINOR IMPROVEMENTS: {len(self.findings)} low-severity issues detected. These are primarily code quality concerns (magic numbers, nested loops) that don't pose immediate risks but should be addressed in refactoring cycles."
