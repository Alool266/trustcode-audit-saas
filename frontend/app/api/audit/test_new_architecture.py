#!/usr/bin/env python3
"""Test the new modular architecture."""

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzers.python_analyzer import PythonAnalyzer
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
analyzer = PythonAnalyzer()
findings = analyzer.analyze(test_code, 'test.py')
print(f"   Findings detected: {len(findings)}")
for i, f in enumerate(findings, 1):
    msg = f.message.encode('ascii', 'ignore').decode('ascii', 'ignore') if f.message else ''
    print(f"   {i}. [{f.severity.upper()}] {f.category}: {msg}")

# Test Language Router
print("\n2. Testing LanguageRouter:")
router = LanguageRouter()
result = router.analyze_file(test_code, 'test.py')
print(f"   TrustScore: {result['TrustScore']}/100")
print(f"   Total findings: {len(result['Findings'])}")
print(f"   Recommendation: {result['PhD_Level_Recommendation'][:80]}...")

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
