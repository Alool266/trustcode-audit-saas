"""
TrustCode AI Audit Engine
Detects Knowledge Conflicting Hallucinations in Python code using AST analysis.
"""

import ast
import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set
from datetime import datetime


class AuditFinding:
    """Represents a single audit finding."""
    
    def __init__(self, category: str, severity: str, message: str, line: int, 
                 snippet: str = "", recommendation: str = ""):
        self.category = category
        self.severity = severity  # 'critical', 'high', 'medium', 'low'
        self.message = message
        self.line = line
        self.snippet = snippet
        self.recommendation = recommendation
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "snippet": self.snippet,
            "recommendation": self.recommendation
        }


class AuditEngine:
    """Core audit engine that analyzes Python code for AI hallucinations."""
    
    # Known correct API signatures (common libraries)
    KNOWN_APIS = {
        'pandas': {
            'read_csv': ['filepath_or_buffer', 'sep', 'delimiter', 'header', 'names', 'index_col'],
            'read_excel': ['io', 'sheet_name', 'header', 'names', 'index_col', 'usecols'],
            'read_json': ['path_or_buf', 'orient', 'typ', 'dtype', 'convert_axes'],
            'DataFrame': ['data', 'index', 'columns', 'dtype', 'copy'],
        },
        'numpy': {
            'array': ['object', 'dtype', 'copy', 'order', 'subok', 'ndmin'],
            'zeros': ['shape', 'dtype', 'order'],
            'ones': ['shape', 'dtype', 'order'],
            'linspace': ['start', 'stop', 'num', 'endpoint', 'retstep', 'dtype', 'axis'],
        },
        'os': {
            'path': ['join', 'exists', 'isfile', 'isdir', 'getsize'],
            'environ': ['get', 'setdefault', 'items', 'keys', 'values'],
        },
        'json': {
            'load': ['fp', 'cls', 'object_hook', 'parse_float', 'parse_int', 'parse_constant'],
            'loads': ['s', 'encoding', 'cls', 'object_hook', 'parse_float', 'parse_int'],
            'dump': ['obj', 'fp', 'skipkeys', 'ensure_ascii', 'check_circular', 'allow_nan'],
        }
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
    ]
    
    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.tree = None
        self.source_code = ""
        self.findings: List[AuditFinding] = []
        self.trust_score = 100
        self.imported_modules: Dict[str, Set[str]] = {}  # module -> set of aliases
        
    def load_file(self) -> bool:
        """Load and parse the Python file."""
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                self.source_code = f.read()
            self.tree = ast.parse(self.source_code)
            # First pass: collect all imports
            self._collect_imports()
            return True
        except Exception as e:
            self.findings.append(AuditFinding(
                category="System",
                severity="critical",
                message=f"Failed to parse file: {str(e)}",
                line=0,
                recommendation="Check file encoding and syntax."
            ))
            return False
    
    def _collect_imports(self):
        """Collect all import statements to map aliases to real module names."""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split('.')[0]  # Get top-level module
                    if module not in self.imported_modules:
                        self.imported_modules[module] = set()
                    alias_name = alias.asname if alias.asname else module
                    self.imported_modules[module].add(alias_name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module = node.module.split('.')[0]  # Get top-level module
                    if module not in self.imported_modules:
                        self.imported_modules[module] = set()
                    for alias in node.names:
                        alias_name = alias.asname if alias.asname else alias.name
                        self.imported_modules[module].add(alias_name)
    
    def analyze(self):
        """Run all analysis checks."""
        if not self.tree:
            return
        
        # Visit all nodes
        for node in ast.walk(self.tree):
            self._check_unknown_apis(node)
            self._check_empty_except(node)
            self._check_nested_loops(node)
            self._check_eval_usage(node)
            self._check_hardcoded_secrets(node)
            self._check_magic_numbers(node)
            self._check_bare_except(node)
        
        # Calculate trust score
        self._calculate_trust_score()
    
    def _check_unknown_apis(self, node: ast.AST):
        """Detect potential API hallucinations (wrong method names)."""
        if isinstance(node, ast.Call):
            # Get the function name being called
            func_name = self._get_call_name(node.func)
            if func_name and '.' in func_name:
                # Split into object and method
                parts = func_name.split('.')
                object_name = parts[0]
                method_name = parts[-1]
                
                # Check if this object corresponds to a known library
                for lib_name, methods in self.KNOWN_APIS.items():
                    # Check if object_name matches the library or any of its aliases
                    if (object_name == lib_name or
                        any(alias == object_name for alias in self.imported_modules.get(lib_name, set()))):
                        # Check if method exists in the library
                        if method_name not in methods:
                            # Check for similar methods (typo detection)
                            similar = self._find_similar(method_name, methods.keys())
                            if similar:  # Only flag if we have good suggestions
                                self.findings.append(AuditFinding(
                                    category="Unknown API",
                                    severity="high",
                                    message=f"Potentially hallucinated method '{method_name}' in {lib_name}. "
                                           f"Did you mean: {', '.join(similar)}?",
                                    line=node.lineno,
                                    snippet=self._get_snippet(node.lineno),
                                    recommendation=f"Verify the {lib_name} API documentation for correct method names."
                                ))
    
    def _check_empty_except(self, node: ast.AST):
        """Flag empty except blocks that silently fail."""
        if isinstance(node, ast.ExceptHandler):
            # Check if body is empty or only contains pass/ellipsis
            if not node.body or all(isinstance(stmt, (ast.Pass, ast.Expr)) and 
                                   (not isinstance(stmt, ast.Expr) or 
                                    isinstance(stmt.value, ast.Constant) and stmt.value.value is ...) 
                                   for stmt in node.body):
                self.findings.append(AuditFinding(
                    category="Silent Logic Failure",
                    severity="medium",
                    message="Empty except block that silently catches all exceptions",
                    line=node.lineno,
                    snippet=self._get_snippet(node.lineno),
                    recommendation="Add specific exception handling or at least log the error."
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
                recommendation="Use 'except Exception:' or catch specific exceptions."
            ))
    
    def _check_nested_loops(self, node: ast.AST):
        """Detect O(n²) nested loops where O(n) might be possible."""
        if isinstance(node, (ast.For, ast.While)):
            # Check if loop body contains another loop
            for child in ast.walk(node):
                if isinstance(child, (ast.For, ast.While)) and child is not node:
                    # Check if both loops iterate over similar data structures
                    # This is a heuristic - we flag nested loops as potential O(n²)
                    self.findings.append(AuditFinding(
                        category="Performance Risk",
                        severity="low",
                        message="Nested loop detected - potential O(n²) complexity",
                        line=node.lineno,
                        snippet=self._get_snippet(node.lineno),
                        recommendation="Consider using dictionaries, sets, or list comprehensions to reduce complexity."
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
                    recommendation="Avoid eval/exec. Use safer alternatives like ast.literal_eval() or specific APIs."
                ))
    
    def _check_hardcoded_secrets(self, node: ast.AST):
        """Detect hardcoded credentials and secrets."""
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    # Check variable name patterns
                    for pattern, secret_type in self.SECRET_PATTERNS:
                        if re.search(pattern, f"{var_name} = ", re.IGNORECASE):
                            self.findings.append(AuditFinding(
                                category="Security",
                                severity="high",
                                message=f"Hardcoded {secret_type} detected",
                                line=node.lineno,
                                snippet=self._get_snippet(node.lineno),
                                recommendation="Use environment variables or secure secret management."
                            ))
                            break
    
    def _check_magic_numbers(self, node: ast.AST):
        """Flag magic numbers (unexplained numeric literals)."""
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            # Skip common numbers: 0, 1, -1, 2, 10, 100, 1000
            if node.value not in [0, 1, -1, 2, 10, 100, 1000, 60, 3600, 24, 7, 30, 365]:
                # Check if it's in a context where it's not assigned to a named constant
                parent = self._find_parent(node)
                if isinstance(parent, ast.Assign):
                    # If assigned to UPPER_CASE variable, it's probably intentional
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
                        recommendation="Replace with named constant for better maintainability."
                    ))
    
    def _find_similar(self, target: str, candidates: List[str]) -> List[str]:
        """Find similar method names using Levenshtein distance."""
        from difflib import get_close_matches
        return get_close_matches(target, candidates, n=3, cutoff=0.6)
    
    def _get_call_name(self, func: ast.AST) -> str:
        """Extract the full function name from a Call node."""
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            # Recursively build the full attribute path
            value_name = self._get_call_name(func.value)
            if value_name:
                return f"{value_name}.{func.attr}"
        return ""
    
    def _find_parent(self, node: ast.AST) -> ast.AST:
        """Find parent node in the tree (simplified)."""
        # This is a simplified version - in production you'd want proper parent tracking
        return None
    
    def _get_snippet(self, line_num: int, context: int = 2) -> str:
        """Extract code snippet around the given line."""
        lines = self.source_code.split('\n')
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = lines[start:end]
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
            'low': 3
        }
        
        for finding in self.findings:
            weight = severity_weights.get(finding.severity, 5)
            score -= weight
        
        # Ensure score doesn't go below 0
        self.trust_score = max(0, score)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate the final JSON report."""
        # Generate PhD-level recommendation based on findings
        recommendation = self._generate_recommendation()
        
        return {
            "TrustScore": self.trust_score,
            "Findings": [f.to_dict() for f in self.findings],
            "PhD_Level_Recommendation": recommendation,
            "AuditMetadata": {
                "file": str(self.filepath),
                "audit_date": datetime.now().isoformat(),
                "engine_version": "1.0.0",
                "total_findings": len(self.findings)
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
        
        if critical_count > 0:
            return f"CRITICAL INTERVENTION REQUIRED: {critical_count} critical issue(s) detected. Immediate refactoring is essential before production deployment. Focus on security vulnerabilities and API correctness. The current code exhibits patterns consistent with AI hallucination artifacts."
        elif high_count > 0:
            return f"HIGH PRIORITY: {high_count} high-severity issue(s) require attention. Address security risks and API misuses. Consider implementing static analysis in CI/CD pipeline to prevent regressions."
        else:
            return f"MODERATE IMPROVEMENT NEEDED: {len(self.findings)} total issues across {len(categories)} categories. While not critical, addressing these will improve code maintainability and reduce technical debt. Focus on performance optimization and error handling robustness."
    
    def save_report(self, output_path: str = "audit_results.json"):
        """Save the audit report to a JSON file."""
        report = self.generate_report()
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[OK] Audit report saved to {output_path}")
        return report


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: python audit_engine.py <python_file> [output_json]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "audit_results.json"
    
    engine = AuditEngine(filepath)
    if engine.load_file():
        engine.analyze()
        report = engine.save_report(output_path)
        
        # Print summary (use ASCII-safe characters for Windows)
        try:
            print(f"\n[AUDIT SUMMARY]")
            print(f"   TrustScore: {report['TrustScore']}/100")
            print(f"   Total Findings: {report['AuditMetadata']['total_findings']}")
            print(f"\n[PHD RECOMMENDATION]: {report['PhD_Level_Recommendation'][:100]}...")
        except UnicodeEncodeError:
            # Fallback for Windows console
            print(f"\n[AUDIT SUMMARY]")
            print(f"   TrustScore: {report['TrustScore']}/100")
            print(f"   Total Findings: {report['AuditMetadata']['total_findings']}")
            print(f"\n[PHD RECOMMENDATION]: {report['PhD_Level_Recommendation'][:100]}...")
    else:
        print("[ERROR] Audit failed due to parsing errors.")
        sys.exit(1)


if __name__ == "__main__":
    main()