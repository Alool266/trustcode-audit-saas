#!/usr/bin/env python3
"""Test the JavaScript analyzer."""

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzers.javascript_analyzer import JavaScriptAnalyzer

# Test code with various issues
test_code = '''
// Sample JavaScript file with AI hallucinations for testing
// This file should trigger multiple findings

const SECRET_API_KEY = "sk-1234567890abcdef"; // Hardcoded secret

function processUserInput(userInput) {
    // XSS vulnerability - using innerHTML
    document.getElementById('output').innerHTML = userInput;
}

function calculate() {
    // Magic number
    let result = 3.14159 * 5;
    return result;
}

function riskyOperation() {
    // Dangerous eval usage
    let code = "alert('Hacked!')";
    eval(code);
}

function executeCommand(cmd) {
    // Command injection risk
    const child_process = require('child_process');
    child_process.exec(cmd);
}

function emptyCatch() {
    try {
        JSON.parse('invalid json');
    } catch (e) {
        // Empty catch block - silently ignores errors
    }
}

function bareExcept() {
    try {
        someUndefinedFunction();
    } except: {
        // Bare except catches everything
    }
}

function nestedLoops() {
    // Nested loops - performance risk
    for (let i = 0; i < 100; i++) {
        for (let j = 0; j < 100; j++) {
            for (let k = 0; k < 100; k++) {
                console.log(i, j, k);
            }
        }
    }
}

// Console.log in production (should be flagged)
console.log("Debug information:", SECRET_API_KEY);

// Loose equality (should be flagged)
if (userInput == "admin") {
    // Allow admin access
}

var oldVariable = "using var instead of let/const"; // var usage
'''

print("=" * 60)
print("Testing JavaScript Analyzer")
print("=" * 60)

# Test JavaScript Analyzer
analyzer = JavaScriptAnalyzer()
findings = analyzer.analyze(test_code, 'test.js')
print(f"Findings detected: {len(findings)}")
for i, f in enumerate(findings, 1):
    msg = f.message.encode('ascii', 'ignore').decode('ascii', 'ignore') if f.message else ''
    print(f"{i}. [{f.severity.upper()}] {f.category}: {msg}")

# Test trust score
trust_score = analyzer.calculate_trust_score(findings)
print(f"\nTrust Score: {trust_score}/100")

# Test recommendation
recommendation = analyzer.generate_recommendation(findings)
print(f"\nRecommendation: {recommendation[:100]}...")

print("\n" + "=" * 60)
print("JavaScript Analyzer test completed!")
print("=" * 60)