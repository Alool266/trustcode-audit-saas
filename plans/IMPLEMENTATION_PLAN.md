# TrustCode AI - Comprehensive Implementation Plan

## Overview

This plan outlines the implementation of three major features:
1. **Multi-Language Support** - Audit code in Python, JavaScript, TypeScript, Java, Go, Rust, C++, and more
2. **Full Codebase Scanning** - Upload entire projects (zip files) with aggregated reports
3. **Enhanced Detailed Reports** - Code flow analysis, dependency graphs, CVSS-like severity scoring, fix suggestions

---

## Architecture Overview

```mermaid
graph TB
    subgraph Frontend
        UI[Next.js UI]
        Upload[File/Zip Upload Component]
        Results[Results Dashboard]
        Report[PDF Report Generator]
    end
    
    subgraph Backend Python Serverless
        Router[API Router]
        ZipHandler[Zip Extractor]
        FileScanner[File Scanner]
        LangRouter[Language Router]
    end
    
    subgraph Language Analyzers
        PyAnalyzer[Python AST Analyzer]
        JSAnalyzer[JS/TS Tree-sitter Analyzer]
        JavaAnalyzer[Java Tree-sitter Analyzer]
        GoAnalyzer[Go Tree-sitter Analyzer]
        RustAnalyzer[Rust Tree-sitter Analyzer]
    end
    
    subgraph Report Engine
        Aggregator[Results Aggregator]
        Scorer[CVSS Scoring Engine]
        GraphBuilder[Dependency Graph Builder]
        PDFGen[PDF Certificate Generator]
    end
    
    UI --> Upload
    Upload --> Router
    Router --> ZipHandler
    ZipHandler --> FileScanner
    FileScanner --> LangRouter
    LangRouter --> PyAnalyzer
    LangRouter --> JSAnalyzer
    LangRouter --> JavaAnalyzer
    LangRouter --> GoAnalyzer
    LangRouter --> RustAnalyzer
    
    PyAnalyzer --> Aggregator
    JSAnalyzer --> Aggregator
    JavaAnalyzer --> Aggregator
    GoAnalyzer --> Aggregator
    RustAnalyzer --> Aggregator
    
    Aggregator --> Scorer
    Scorer --> GraphBuilder
    GraphBuilder --> PDFGen
    PDFGen --> Results
    Results --> Report
```

---

## Phase 1: Multi-Language Support

### 1.1 Technology Choice: Tree-sitter

Tree-sitter is a parser generator tool and incremental parsing library that can parse code from multiple languages into a concrete syntax tree. It supports:
- Python, JavaScript, TypeScript, JSX, TSX
- Java, Go, Rust, C, C++, C#
- Ruby, PHP, Swift, Kotlin, and more

### 1.2 Implementation Strategy

Since Vercel serverless functions have limitations with native modules, we'll use a **hybrid approach**:

**Option A: Pure Python with tree-sitter Python bindings**
- Use `tree-sitter` Python package with language grammars
- Compile grammars at build time
- Works within Vercel's Python runtime

**Option B: Language-specific regex + pattern matching**
- Fallback approach if tree-sitter is too heavy
- Less accurate but simpler to deploy

**Recommendation: Option A** - Use tree-sitter for accurate AST parsing

### 1.3 New Files to Create

```
trustcode-audit-saas/frontend/app/api/audit/
├── analyzers/
│   ├── __init__.py
│   ├── base_analyzer.py          # Abstract base class for all analyzers
│   ├── python_analyzer.py        # Existing audit_engine.py refactored
│   ├── javascript_analyzer.py    # JS/TS analysis using tree-sitter
│   ├── java_analyzer.py          # Java analysis
│   ├── go_analyzer.py            # Go analysis
│   └── rust_analyzer.py          # Rust analysis
├── language_router.py            # Routes files to appropriate analyzer
└── route.py                      # Updated main route
```

### 1.4 Base Analyzer Interface

```python
# base_analyzer.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class AuditFinding:
    category: str
    severity: str
    message: str
    line: int
    column: int
    file_path: str
    snippet: str
    recommendation: str
    cwe_id: str = ""  # Common Weakness Enumeration

class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, source_code: str, file_path: str) -> List[AuditFinding]:
        pass
    
    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        pass
    
    @abstractmethod
    def get_language_name(self) -> str:
        pass
```

### 1.5 Detection Rules Per Language

| Rule Category | Python | JS/TS | Java | Go | Rust |
|--------------|--------|-------|------|-----|------|
| eval/exec usage | eval, exec | eval, Function, setTimeout(string) | ScriptEngine | - | - |
| Hardcoded secrets | password=, api_key= | password=, apiKey=, secret= | password=, secret= | password=, apiKey= | password=, api_key= |
| Unsafe deserialization | pickle.loads, yaml.load | JSON.parse (untrusted) | ObjectInputStream | json.Unmarshal (untrusted) | serde (untrusted) |
| SQL Injection | f-string SQL | template literal SQL | String concatenation SQL | fmt.Sprintf SQL | format! SQL |
| XSS | - | innerHTML, dangerouslySetInnerHTML | response.getWriter | - | - |
| Path Traversal | open(user_input) | fs.readFile(user_input) | new File(user_input) | os.Open(user_input) | fs::File::open |
| Command Injection | os.system, subprocess | child_process.exec | Runtime.exec | exec.Command | Command::new |
| Empty catch | except: | catch(e) {} | catch(Exception e) {} | - | - |
| Bare except | except: | - | - | - | - |
| Magic numbers | Yes | Yes | Yes | Yes | Yes |
| Unknown APIs | Yes | Yes | Yes | Yes | Yes |
| Insecure randomness | random.random() | Math.random() | java.util.Random | math/rand | rand::random() |
| SSRF | requests.get(user_url) | fetch(user_url) | HttpClient(user_url) | http.Get(user_url) | reqwest::get(user_url) |
| Open redirect | redirect(user_url) | window.location | sendRedirect | http.Redirect | redirect |
| Cryptographic weakness | MD5, SHA1, DES | crypto.createHash('md5') | MessageDigest.getInstance("MD5") | md5.Sum | md5::compute |
| Null pointer risk | - | undefined access | .get() without null check | panic on nil | unwrap() on Option |
| Race condition | threading without lock | async without await | synchronized missing | goroutine without sync | Arc without Mutex |
| Resource leak | file not closed | event listeners not removed | stream not closed | goroutine leak | memory leak |
| Type confusion | - | any type usage | raw types | interface{} | Any type |

---

### 1.6 AST-Based Data Flow Analysis (Taint Tracking)

**Objective**: Track untrusted user input as it flows through the code to identify vulnerabilities.

**Implementation**:
```python
class TaintAnalyzer:
    def __init__(self):
        self.tainted_variables = {}  # var_name -> source (e.g., "request.GET['param']")
        self.propagation_paths = []  # List of (from, to, operation)
    
    def track_user_input(self, node: ast.AST) -> List[str]:
        """Identify sources of user input (request params, file reads, etc.)"""
        sources = []
        if isinstance(node, ast.Call):
            if self.is_user_input_source(node):
                sources.append(self.extract_variable_assignment(node))
        return sources
    
    def propagate_taint(self, node: ast.AST, tainted_vars: Set[str]):
        """Propagate taint through assignments and operations"""
        # Track variable assignments: x = y (if y is tainted, x becomes tainted)
        # Track function calls: if argument is tainted, parameter becomes tainted
        # Track returns: if return value uses tainted data, caller receives taint
        pass
    
    def check_sink(self, node: ast.AST, tainted_vars: Set[str]) -> List[AuditFinding]:
        """Check if tainted data reaches a dangerous sink (SQL, exec, file write)"""
        sinks = []
        if self.is_dangerous_sink(node):
            used_vars = self.extract_variables_in_call(node)
            tainted_used = [v for v in used_vars if v in tainted_vars]
            if tainted_used:
                sinks.append(self.create_finding(node, tainted_used))
        return sinks
```

**Sources to Track**:
- HTTP request parameters (Flask.request, Django.request, Express.req)
- File system reads
- Environment variables
- Command-line arguments
- Network inputs

**Sinks to Monitor**:
- Database queries (SQL execution)
- Command execution (os.system, subprocess, child_process.exec)
- File operations (open, write)
- HTML rendering (template engines, innerHTML)
- Deserialization (pickle, JSON.parse with eval)

---

### 1.7 Custom Rule Engine

Allow users to define custom detection rules in YAML/JSON format.

**Rule Format**:
```yaml
rule:
  id: "CUSTOM-001"
  name: "Hardcoded AWS Secret"
  description: "Detects hardcoded AWS access keys"
  severity: "critical"
  category: "Security"
  
  pattern:
    type: "regex"
    expression: 'AKIA[0-9A-Z]{16}'
    
  # OR use AST pattern matching
  ast:
    pattern: |
      Assign
        targets: [Name(id="AWS_SECRET_ACCESS_KEY")]
        value: [Constant(value=~"AKIA[0-9A-Z]{16}")]
    
  # Optional: context conditions
  conditions:
    - variable_name: "AWS_SECRET_ACCESS_KEY"
    - file_extension: ".py"
    
  # False positive filters
  false_positive_filters:
    - "test_"
    - "mock_"
    - "fixture_"
    
  remediation:
    message: "Use AWS Secrets Manager or environment variables"
    code_example: |
      # Bad
      aws_key = "AKIAIOSFODNN7EXAMPLE"
      
      # Good
      aws_key = os.environ.get("AWS_ACCESS_KEY_ID")
```

**Implementation**:
```python
class CustomRuleEngine:
    def __init__(self, rules_dir: Path):
        self.rules = self.load_rules(rules_dir)
    
    def load_rules(self, rules_dir: Path) -> List[CustomRule]:
        rules = []
        for rule_file in rules_dir.glob("*.yaml"):
            with open(rule_file) as f:
                rule_data = yaml.safe_load(f)
                rules.append(CustomRule.from_dict(rule_data['rule']))
        return rules
    
    def apply_rules(self, source_code: str, language: str, ast_tree=None) -> List[AuditFinding]:
        findings = []
        for rule in self.rules:
            if rule.matches_language(language):
                if rule.pattern.type == 'regex':
                    matches = re.finditer(rule.pattern.expression, source_code)
                    for match in matches:
                        if not self.is_false_positive(match, rule):
                            findings.append(self.create_finding(match, rule))
                elif rule.pattern.type == 'ast' and ast_tree:
                    matches = self.match_ast_pattern(ast_tree, rule.ast.pattern)
                    for match in matches:
                        findings.append(self.create_finding(match, rule))
        return findings
```

---

### 1.8 False Positive Reduction

**Context-Aware Analysis**:
1. **Test file detection**: Skip findings in files matching `test_*.py`, `*_test.py`, `tests/`
2. **Mock/fixture detection**: Ignore variables with names containing `mock_`, `fake_`, `fixture_`, `dummy_`
3. **Example code detection**: Skip files in `examples/`, `docs/`, `samples/` directories
4. **Comment-based suppressions**: Allow `# nosec` or `# trustcode-ignore` comments
5. **Configuration-based whitelisting**: Allow users to specify patterns to ignore

**Implementation**:
```python
class FalsePositiveReducer:
    def __init__(self):
        self.test_patterns = [
            r'^test_.*\.py$',
            r'.*_test\.py$',
            r'^.*\.test\.py$',
        ]
        self.mock_patterns = [
            r'mock_',
            r'fake_',
            r'fixture_',
            r'dummy_',
            r'stub_',
        ]
    
    def is_likely_false_positive(self, finding: AuditFinding, file_path: str) -> bool:
        # Check if file is a test file
        if self.is_test_file(file_path):
            return True
        
        # Check if variable/method name indicates mock/test data
        if self.is_mock_indicator(finding):
            return True
        
        # Check for suppression comments in code snippet
        if self.has_suppression_comment(finding):
            return True
        
        # Check if finding is in example/documentation code
        if self.is_example_file(file_path):
            return True
        
        return False
    
    def is_test_file(self, file_path: str) -> bool:
        path = Path(file_path)
        return any(re.match(pattern, path.name) for pattern in self.test_patterns) or \
               any(part in path.parts for part in ['test', 'tests', '__tests__', 'spec'])
    
    def has_suppression_comment(self, finding: AuditFinding) -> bool:
        # Look for # nosec, # trustcode-ignore, etc. in the snippet
        suppression_patterns = [r'nosec', r'trustcode-ignore', r'noqa']
        for pattern in suppression_patterns:
            if re.search(pattern, finding.snippet, re.IGNORECASE):
                return True
        return False
```

---

## Phase 2: Full Codebase Scanning (Continued)

### 2.5 Zip Handler Implementation

```python
# zip_handler.py
import zipfile
import tempfile
from pathlib import Path
import shutil

class ZipHandler:
    MAX_ZIP_SIZE = 50_000_000  # 50MB
    MAX_EXTRACTED_SIZE = 100_000_000  # 100MB
    MAX_FILES = 500
    
    def extract_zip(self, zip_path: Path, extract_to: Path) -> List[Path]:
        """Extract zip file and return list of extracted file paths."""
        # Validate zip size
        if zip_path.stat().st_size > self.MAX_ZIP_SIZE:
            raise ValueError(f"Zip file too large (max {self.MAX_ZIP_SIZE} bytes)")
        
        # Create extraction directory
        extract_to.mkdir(exist_ok=True)
        
        extracted_files = []
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Check total size
            total_size = sum(info.file_size for info in zip_ref.infolist())
            if total_size > self.MAX_EXTRACTED_SIZE:
                raise ValueError(f"Extracted size too large (max {self.MAX_EXTRACTED_SIZE} bytes)")
            
            # Extract files
            for member in zip_ref.namelist():
                # Security: prevent path traversal
                member_path = Path(member).resolve()
                if not str(member_path).startswith(str(extract_to.resolve())):
                    continue
                
                # Skip directories
                if member.endswith('/'):
                    continue
                
                # Extract file
                zip_ref.extract(member, extract_to)
                extracted_files.append(extract_to / member)
        
        return extracted_files
```

---

## Phase 3: Enhanced Detailed Reports (Continued)

### 3.5 CVSS Scoring Engine

```python
# cvss_scorer.py
class CVSSScorer:
    """
    Simplified CVSS v3.1 scoring based on:
    - Attack Vector (AV): Network (0.85), Adjacent (0.62), Local (0.55), Physical (0.2)
    - Attack Complexity (AC): Low (0.77), High (0.44)
    - Privileges Required (PR): None (0.85), Low (0.62), High (0.27)
    - User Interaction (UI): None (0.85), Required (0.62)
    - Scope (S): Unchanged (0), Changed (1)
    - Confidentiality (C): High (0.56), Low (0.22), None (0)
    - Integrity (I): High (0.56), Low (0.22), None (0)
    - Availability (A): High (0.56), Low (0.22), None (0)
    """
    
    def calculate_score(self, finding: AuditFinding, context: Dict) -> float:
        # Base score from severity
        base_scores = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.5
        }
        score = base_scores.get(finding.severity.lower(), 5.0)
        
        # Adjust based on context
        if finding.category == 'SQL Injection':
            score = max(score, 8.5)  # SQLi is usually critical
        elif finding.category == 'XSS':
            score = max(score, 6.5)
        elif finding.category == 'Command Injection':
            score = max(score, 9.0)
        elif finding.category == 'Hardcoded Secret':
            score = max(score, 7.0)
        
        # Reduce score if in test file
        if context.get('is_test_file', False):
            score *= 0.5
        
        # Round to 1 decimal
        return round(min(10.0, score), 1)
```

---

## Implementation Order (Updated)

### Sprint 1: Foundation (Week 1-2)
1. Create `base_analyzer.py` with abstract interface
2. Refactor existing `audit_engine.py` into `python_analyzer.py`
3. Create `language_router.py` to route files to analyzers
4. Implement `false_positive_reducer.py`
5. Update `route.py` to use new architecture
6. Test with Python files

### Sprint 2: JavaScript/TypeScript Support (Week 3)
1. Add tree-sitter dependency to requirements
2. Create `javascript_analyzer.py` with JS/TS detection rules
3. Create `tree_sitter_wrapper.py` for language-agnostic AST parsing
4. Test with sample JS/TS files

### Sprint 3: Additional Languages (Week 4)
1. Create `java_analyzer.py`
2. Create `go_analyzer.py`
3. Create `rust_analyzer.py`
4. Test with sample files in each language

### Sprint 4: Zip Upload & Project Scanning (Week 5)
1. Create `zip_handler.py` for extraction
2. Create `project_scanner.py` for multi-file scanning
3. Create `file_filter.py` for intelligent file discovery
4. Update frontend to accept zip uploads
5. Implement file tree UI component

### Sprint 5: Enhanced Reports (Week 6-7)
1. Implement `cvss_scorer.py`
2. Create `dependency_graph.py` for finding relationships
3. Create `remediation_planner.py` for prioritized fixes
4. Update PDF generator with new report format
5. Add charts and visualizations

### Sprint 6: Custom Rule Engine (Week 8)
1. Design YAML rule format
2. Implement `custom_rule_engine.py`
3. Add rule management UI (upload, enable/disable rules)
4. Document rule creation guide

### Sprint 7: Frontend UI Updates (Week 9)
1. Update upload component for zip files
2. Create file tree view with expand/collapse
3. Add filtering by file, severity, category
4. Add sorting and search
5. Implement charts (severity distribution, language breakdown)
6. Update results display with new data structure

### Sprint 8: Testing & Optimization (Week 10)
1. Test with real-world multi-language projects
2. Performance optimization (caching, streaming)
3. False positive tuning based on feedback
4. Vercel deployment testing and optimization
5. Load testing with large codebases

### Sprint 9: Documentation & Deployment (Week 11)
1. Update README with new features
2. Create user guide for custom rules
3. Add API documentation
4. Create demo videos
5. Deploy to production

---

## File Modification Summary (Updated)

### New Files to Create (25 files)
```
frontend/app/api/audit/analyzers/__init__.py
frontend/app/api/audit/analyzers/base_analyzer.py
frontend/app/api/audit/analyzers/python_analyzer.py
frontend/app/api/audit/analyzers/javascript_analyzer.py
frontend/app/api/audit/analyzers/java_analyzer.py
frontend/app/api/audit/analyzers/go_analyzer.py
frontend/app/api/audit/analyzers/rust_analyzer.py
frontend/app/api/audit/analyzers/cpp_analyzer.py (optional)
frontend/app/api/audit/language_router.py
frontend/app/api/audit/zip_handler.py
frontend/app/api/audit/project_scanner.py
frontend/app/api/audit/file_filter.py
frontend/app/api/audit/cvss_scorer.py
frontend/app/api/audit/dependency_graph.py
frontend/app/api/audit/remediation_planner.py
frontend/app/api/audit/false_positive_reducer.py
frontend/app/api/audit/custom_rule_engine.py
frontend/app/api/audit/tree_sitter_wrapper.py
frontend/app/api/audit/rules/              # Directory for custom rules
│   ├── security_rules.yaml
│   ├── best_practices.yaml
│   └── custom_example.yaml
frontend/app/api/audit/requirements.txt (updated)
```

### Files to Modify (8 files)
```
frontend/app/api/audit/route.py - Updated to use new architecture
frontend/app/page.tsx - Updated UI for zip upload, file tree, enhanced results
frontend/app/globals.css - Additional styles for file tree, charts, filtering
frontend/vercel.json - Updated build configuration
frontend/package.json - Add new dependencies (recharts, react-syntax-highlighter, jszip)
frontend/README.md - Update with new features
frontend/app/api/sample-results/route.ts - Update sample data format
frontend/app/api/generate-certificate/route.ts - Update to use new report format
```

### Dependencies to Add

**Python**:
```
tree-sitter==0.21.3
tree-sitter-languages==1.10.2
pyyaml==6.0.1
```

**Frontend**:
```
recharts^2.10.3
react-syntax-highlighter^15.5.0
jszip^3.10.1
```

---

## Risk Assessment (Updated)

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| tree-sitter too large for Vercel | High | Medium | Use pre-compiled grammars, lazy loading, fallback to regex |
| Zip extraction exceeds memory/disk | High | Medium | Stream processing, strict size limits, early rejection |
| PDF generation too slow with large reports | Medium | High | Generate asynchronously, show progress, allow background download |
| False positives increase with more rules | Medium | High | Implement false positive reducer, allow custom whitelisting |
| Vercel serverless timeout (10s) | High | High | Process files in parallel, use streaming responses, increase timeout |
| Multi-language support complexity | Medium | High | Start with 2-3 languages, expand incrementally |
| User confusion with complex UI | Medium | Medium | Progressive disclosure, tooltips, guided tours |

---

## Success Criteria (Updated)

1. **Multi-Language**: Successfully audit Python, JS, TS, Java, Go, Rust with 20+ detection rules per language
2. **Codebase Scanning**: Handle zip files up to 50MB with 500+ files, complete scan in <30s
3. **Enhanced Reports**: PDF includes CVSS scores (0-10), CWE references, fix suggestions, dependency graphs
4. **False Positive Rate**: <10% on clean codebases, <5% with custom rules
5. **Custom Rules**: Users can create and deploy custom YAML rules without code changes
6. **Performance**: 90th percentile scan time <30s, memory <256MB for typical projects
7. **Usability**: Users can understand and act on findings within 5 minutes

---

## Next Steps

1. **Review and approve this comprehensive plan**
2. **Switch to Code mode for implementation**
3. **Start with Sprint 1: Foundation**
   - Create base analyzer interface
   - Refactor Python analyzer
   - Build language router
4. **Test each sprint thoroughly before proceeding**
5. **Iterate based on feedback**

The plan covers all requested features:
- ✅ Multi-language support (Python, JS/TS, Java, Go, Rust, C++)
- ✅ Full codebase scanning (zip uploads, project aggregation)
- ✅ Detailed reports (CVSS scoring, dependency graphs, fix suggestions)
- ✅ AST-based data flow analysis (taint tracking)
- ✅ Custom rule engine (YAML-based)
- ✅ False positive reduction (context-aware)

Ready to begin implementation?

---

## Phase 2: Full Codebase Scanning

### 2.1 Zip Upload Support

**Frontend Changes:**
- Add zip file upload option alongside single file upload
- Show progress bar for extraction and scanning
- Display file tree of scanned project

**Backend Changes:**
- Accept zip files in addition to single files
- Extract zip to temporary directory
- Recursively scan all supported files
- Aggregate results across all files

### 2.2 New Files to Create

```
trustcode-audit-saas/frontend/app/api/audit/
├── zip_handler.py                # Zip extraction and file discovery
├── project_scanner.py            # Orchestrates scanning of multiple files
└── file_filter.py                # Filters files by extension, ignores node_modules, etc.
```

### 2.3 Project Scanner Logic

```python
# project_scanner.py
class ProjectScanner:
    SUPPORTED_EXTENSIONS = {
        '.py', '.js', '.jsx', '.ts', '.tsx',
        '.java', '.go', '.rs', '.c', '.cpp', '.h', '.hpp'
    }
    
    IGNORED_DIRS = {
        'node_modules', '.git', '__pycache__', 'venv',
        '.venv', 'dist', 'build', 'target', 'vendor',
        '.next', '.nuxt', '.svelte-kit'
    }
    
    MAX_FILE_SIZE = 1_000_000  # 1MB per file
    MAX_FILES = 500  # Maximum files per scan
    
    def scan_directory(self, directory: Path) -> ProjectAuditResult:
        files = self.discover_files(directory)
        results = []
        
        for file_path in files:
            analyzer = self.get_analyzer(file_path)
            if analyzer:
                with open(file_path, 'r') as f:
                    source = f.read()
                findings = analyzer.analyze(source, str(file_path))
                results.extend(findings)
        
        return self.aggregate_results(results, directory)
```

### 2.4 Frontend UI Changes

**Upload Component:**
- Accept both `.py` and `.zip` files
- Show file type selector or auto-detect
- Display "Scanning X files..." progress

**Results Display:**
- Group findings by file
- Show file tree with color-coded severity indicators
- Allow filtering by file, severity, category
- Show aggregate statistics

---

## Phase 3: Enhanced Detailed Reports

### 3.1 CVSS-like Severity Scoring

Replace simple severity labels with numerical scores:

| Score | Severity | Description |
|-------|----------|-------------|
| 9.0-10.0 | Critical | Immediate exploitation risk |
| 7.0-8.9 | High | Significant security vulnerability |
| 4.0-6.9 | Medium | Potential security or quality issue |
| 0.1-3.9 | Low | Code quality or style concern |
| 0.0 | Info | Informational finding |

### 3.2 Enhanced Audit Result Structure

```typescript
interface AuditResult {
  // Existing fields
  TrustScore: number;
  Findings: AuditFinding[];
  PhD_Level_Recommendation: string;
  AuditMetadata: AuditMetadata;
  
  // New fields
  ProjectSummary: ProjectSummary;
  DependencyGraph: DependencyNode[];
  SeverityDistribution: SeverityDistribution;
  CategoryBreakdown: CategoryBreakdown[];
  FileRiskScores: FileRiskScore[];
  RemediationPlan: RemediationStep[];
}

interface AuditFinding {
  category: string;
  severity: string;
  cvssScore: number;
  message: string;
  line: number;
  column: number;
  filePath: string;
  snippet: string;
  recommendation: string;
  cweId: string;
  fixSuggestion: string;
  relatedFindings: number[];
}

interface ProjectSummary {
  totalFiles: number;
  totalLines: number;
  languages: string[];
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
}

interface RemediationStep {
  priority: number;
  findingId: number;
  action: string;
  estimatedEffort: 'quick' | 'moderate' | 'significant';
  codeExample: string;
}
```

### 3.3 Dependency Graph Builder

```python
class DependencyGraphBuilder:
    def build(self, findings: List[AuditFinding]) -> List[DependencyNode]:
        """Build a graph of related findings to show attack paths."""
        # Group findings by file
        # Find relationships between findings
        # Build directed graph of risk propagation
        pass
```

### 3.4 Enhanced PDF Report

The PDF certificate will include:
1. **Cover Page** - TrustCode branding, TrustScore, project name, date
2. **Executive Summary** - High-level overview with charts
3. **Severity Distribution** - Pie chart of findings by severity
4. **File Risk Scores** - Table of files ranked by risk
5. **Detailed Findings** - Each finding with:
   - File path and line number
   - Code snippet with syntax highlighting
   - CVSS score and justification
   - CWE reference link
   - Specific fix suggestion with code example
6. **Remediation Plan** - Prioritized list of fixes
7. **Dependency Graph** - Visual representation of related issues
8. **Appendix** - Full raw data, methodology, references

---

## Implementation Order

### Sprint 1: Foundation (Week 1)
1. Create `base_analyzer.py` with abstract interface
2. Refactor existing `audit_engine.py` into `python_analyzer.py`
3. Create `language_router.py` to route files to analyzers
4. Update `route.py` to use the new architecture

### Sprint 2: JavaScript/TypeScript Support (Week 2)
1. Add tree-sitter dependency to requirements
2. Create `javascript_analyzer.py` with JS/TS detection rules
3. Test with sample JS/TS files

### Sprint 3: Zip Upload & Project Scanning (Week 3)
1. Create `zip_handler.py` for extraction
2. Create `project_scanner.py` for multi-file scanning
3. Create `file_filter.py` for intelligent file discovery
4. Update frontend to accept zip uploads

### Sprint 4: Enhanced Reports (Week 4)
1. Update data structures for enhanced findings
2. Implement CVSS scoring engine
3. Create dependency graph builder
4. Update PDF generator with new report format

### Sprint 5: Frontend UI Updates (Week 5)
1. Update upload component for zip files
2. Create file tree view for project results
3. Add filtering and sorting capabilities
4. Update results display with new data structure

### Sprint 6: Testing & Deployment (Week 6)
1. Test with real-world projects in multiple languages
2. Optimize for Vercel serverless constraints
3. Deploy and verify end-to-end workflow

---

## File Modification Summary

### New Files to Create (15 files)
```
frontend/app/api/audit/analyzers/__init__.py
frontend/app/api/audit/analyzers/base_analyzer.py
frontend/app/api/audit/analyzers/python_analyzer.py
frontend/app/api/audit/analyzers/javascript_analyzer.py
frontend/app/api/audit/analyzers/java_analyzer.py
frontend/app/api/audit/analyzers/go_analyzer.py
frontend/app/api/audit/analyzers/rust_analyzer.py
frontend/app/api/audit/language_router.py
frontend/app/api/audit/zip_handler.py
frontend/app/api/audit/project_scanner.py
frontend/app/api/audit/file_filter.py
frontend/app/api/audit/cvss_scorer.py
frontend/app/api/audit/dependency_graph.py
frontend/app/api/audit/remediation_planner.py
frontend/app/api/audit/requirements.txt (updated)
```

### Files to Modify (5 files)
```
frontend/app/api/audit/route.py - Updated to use new architecture
frontend/app/page.tsx - Updated UI for zip upload and enhanced results
frontend/app/globals.css - Additional styles for file tree and filtering
frontend/vercel.json - Updated build configuration
frontend/package.json - Add new dependencies
```

### Dependencies to Add
```
# Python
tree-sitter==0.21.3
tree-sitter-languages==1.10.2
zipfile36 (built-in)

# Frontend
jszip - For client-side zip handling (optional)
recharts - For charts in results dashboard
react-syntax-highlighter - For code highlighting
```

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| tree-sitter too large for Vercel | High | Use pre-compiled grammars, fallback to regex |
| Zip extraction exceeds memory | Medium | Stream processing, limit file count |
| PDF generation too slow | Medium | Generate asynchronously, cache results |
| False positives in detection | Low | Tune rules, add confidence scores |
| Vercel serverless timeout | High | Process in chunks, use streaming |

---

## Success Criteria

1. **Multi-Language**: Successfully audit Python, JS, TS, Java, Go, Rust files
2. **Codebase Scanning**: Handle zip files up to 50MB with 500+ files
3. **Enhanced Reports**: PDF includes CVSS scores, CWE references, fix suggestions
4. **Performance**: Complete scan within 30 seconds for typical projects
5. **Accuracy**: Less than 10% false positive rate on clean code

---

## Next Steps

1. Review and approve this plan
2. Switch to Code mode for implementation
3. Start with Sprint 1: Foundation
4. Test each sprint before proceeding to next
