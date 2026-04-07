#!/usr/bin/env python3
"""Test the new modular architecture."""

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzers.python_analyzer import PythonAnalyzer
from analyzers.javascript_analyzer import JavaScriptAnalyzer
from language_router import LanguageRouter
from analyzers.false_positive_reducer import FalsePositiveReducer

# Test code with various issues
test_code = '''
import os
import requests

# Hardcoded secret
password = "secret123"

# Eval usage
def risky():
    eval("2+2")

# Empty except
try:
    x = 1/0
except:
    pass

# Nested loops
for i in range(10):
    for j in range(10):
        print(i, j)

# Magic number
def calculate():
    return x * 3.14159
'''

print("=" * 60)
print("Testing New Modular Architecture")
print("=" * 60)

# Test Python Analyzer
print("\n1. Testing PythonAnalyzer:")
py_analyzer = PythonAnalyzer()
py_findings = py_analyzer.analyze(test_code, 'test.py')
print(f"   Findings detected: {len(py_findings)}")
for i, f in enumerate(py_findings, 1):
    msg = f.message.encode('ascii', 'ignore').decode('ascii', 'ignore') if f.message else ''
    print(f"   {i}. [{f.severity.upper()}] {f.category}: {msg}")

# Test JavaScript Analyzer
print("\n2. Testing JavaScriptAnalyzer:")
js_analyzer = JavaScriptAnalyzer()
js_test_code = '''
const SECRET = "key123";
function risky() { eval("alert(1)"); }
console.log("debug");
'''
js_findings = js_analyzer.analyze(js_test_code, 'test.js')
print(f"   Findings detected: {len(js_findings)}")
for i, f in enumerate(js_findings, 1):
    msg = f.message.encode('ascii', 'ignore').decode('ascii', 'ignore') if f.message else ''
    print(f"   {i}. [{f.severity.upper()}] {f.category}: {msg}")

# Test Language Router
print("\n3. Testing LanguageRouter:")
router = LanguageRouter()
print(f"   Supported extensions: {', '.join(router.get_supported_extensions())}")
print(f"   Registered analyzers: {len(set(router._analyzers.values()))}")

# Test with Python file
py_result = router.analyze_file(test_code, 'test.py')
print(f"\n   Python file analysis:")
print(f"   TrustScore: {py_result['TrustScore']}/100")
print(f"   Total findings: {len(py_result['Findings'])}")

# Test with JavaScript file
js_result = router.analyze_file(js_test_code, 'test.js')
print(f"\n   JavaScript file analysis:")
print(f"   TrustScore: {js_result['TrustScore']}/100")
print(f"   Total findings: {len(js_result['Findings'])}")

# Test False Positive Reducer
print("\n3. Testing FalsePositiveReducer:")
reducer = FalsePositiveReducer()
filtered = reducer.filter_findings(result['Findings'], 'test.py')
print(f"   Findings before filtering: {len(result['Findings'])}")
print(f"   Findings after filtering: {len(filtered)}")
print(f"   False positives removed: {len(result['Findings']) - len(filtered)}")

# Test with test file (should be filtered)
test_file_code = '''
def test_something():
    assert True
'''
print("\n4. Testing test file filtering:")
test_finding = analyzer.analyze(test_file_code, 'test_example.py')
print(f"   Findings in test file: {len(test_finding)}")
filtered_test = reducer.filter_findings(test_finding, 'test_example.py')
print(f"   After filtering: {len(filtered_test)}")

print("\n" + "=" * 60)
print("All tests completed successfully!")
print("=" * 60)
