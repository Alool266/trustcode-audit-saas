#!/usr/bin/env python3
"""
TrustCode AI - Complete Workflow Test
Tests the entire pipeline: Audit -> Certificate -> Web UI
"""

import json
import subprocess
import sys
from pathlib import Path

def test_audit_engine():
    """Test the audit engine with sample code."""
    print("\n" + "="*60)
    print("TEST 1: Audit Engine")
    print("="*60)
    
    sample_code = Path("src/sample_code.py")
    output_json = Path("src/audit_results.json")
    
    if not sample_code.exists():
        print(f"❌ Sample code not found: {sample_code}")
        return False
    
    result = subprocess.run(
        [sys.executable, "audit_engine.py", str(sample_code), str(output_json)],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"[ERROR] Audit engine failed:\n{result.stderr}")
        return False
    
    if not output_json.exists():
        print(f"❌ Output JSON not created")
        return False
    
    with open(output_json) as f:
        data = json.load(f)
    
    print(f"[OK] Audit completed successfully")
    print(f"   TrustScore: {data['TrustScore']}/100")
    print(f"   Total Findings: {data['AuditMetadata']['total_findings']}")
    print(f"   Critical Issues: {len([f for f in data['Findings'] if f['severity'] == 'critical'])}")
    
    return True

def test_certificate_generator():
    """Test the certificate generator."""
    print("\n" + "="*60)
    print("TEST 2: Certificate Generator")
    print("="*60)
    
    input_json = Path("src/audit_results.json")
    output_docx = Path("src/TrustCode_Certificate.docx")
    
    if not input_json.exists():
        print(f"❌ Audit results not found: {input_json}")
        return False
    
    result = subprocess.run(
        [sys.executable, "generate_certificate.py", str(input_json), str(output_docx)],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"[ERROR] Certificate generator failed:\n{result.stderr}")
        return False
    
    if not output_docx.exists():
        print(f"❌ Certificate not created")
        return False
    
    file_size = output_docx.stat().st_size
    print(f"[OK] Certificate generated successfully")
    print(f"   File: {output_docx}")
    print(f"   Size: {file_size:,} bytes")
    
    return True

def test_web_ui():
    """Test the web UI components."""
    print("\n" + "="*60)
    print("TEST 3: Web UI Components")
    print("="*60)
    
    ui_dir = Path("../../trustcode-ui")
    
    checks = [
        ("Page component", ui_dir / "app" / "page.tsx"),
        ("Globals CSS", ui_dir / "app" / "globals.css"),
        ("Audit API", ui_dir / "app" / "api" / "audit" / "route.ts"),
        ("Certificate API", ui_dir / "app" / "api" / "generate-certificate" / "route.ts"),
        ("Sample Results API", ui_dir / "app" / "api" / "sample-results" / "route.ts"),
    ]
    
    all_ok = True
    for name, path in checks:
        if path.exists():
            print(f"[OK] {name}: {path.name}")
        else:
            print(f"[ERROR] {name}: missing")
            all_ok = False
    
    return all_ok

def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("TRUSTCODE AI - COMPLETE WORKFLOW TEST")
    print("="*60)
    
    tests = [
        test_audit_engine,
        test_certificate_generator,
        test_web_ui,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"[ERROR] Test failed with exception: {e}")
            results.append(False)
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Tests passed: {passed}/{total}")
    
    if all(results):
        print("\n[SUCCESS] ALL TESTS PASSED!")
        print("\nNext steps:")
        print("1. Start the Next.js UI: cd trustcode-ui && npm run dev")
        print("2. Open http://localhost:3000 in your browser")
        print("3. Upload a Python file to audit")
        print("4. Download the generated certificate")
    else:
        print("\n[WARNING] Some tests failed. Please review the output above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())