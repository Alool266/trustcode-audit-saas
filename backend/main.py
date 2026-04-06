"""
FastAPI backend for TrustCode AI Audit SaaS.
Provides REST endpoints for code auditing and certificate generation.
"""

import os
import sys
import json
import uuid
from pathlib import Path
from typing import List, Dict, Any

from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from audit_engine import AuditEngine
from generate_certificate_pdf import PDFCertificateGenerator

app = FastAPI(
    title="TrustCode AI Audit API",
    description="Backend API for code auditing and certificate generation",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Storage for audit results and certificates
UPLOAD_DIR = Path("uploads")
CERT_DIR = Path("certificates")
UPLOAD_DIR.mkdir(exist_ok=True)
CERT_DIR.mkdir(exist_ok=True)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "TrustCode AI Audit Backend"}


@app.post("/api/audit")
async def audit_code(file: UploadFile = File(...)):
    """
    Audit a Python file for AI hallucinations and code quality issues.

    Args:
        file: Uploaded Python file (.py)

    Returns:
        JSON with audit results including TrustScore and findings
    """
    if not file.filename or not file.filename.endswith('.py'):
        raise HTTPException(status_code=400, detail="Only Python (.py) files are supported")

    # Save uploaded file
    file_id = str(uuid.uuid4())
    file_path = UPLOAD_DIR / f"{file_id}.py"

    try:
        content = await file.read()
        with open(file_path, 'wb') as f:
            f.write(content)

        # Run audit engine
        engine = AuditEngine(str(file_path))
        engine.load_file()
        engine.analyze()
        report = engine.generate_report()

        # Store report for certificate generation
        report_path = UPLOAD_DIR / f"{file_id}_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        return JSONResponse(content=report)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")
    finally:
        # Clean up uploaded file (keep report for certificate generation)
        if file_path.exists():
            file_path.unlink()


@app.post("/api/generate-certificate")
async def generate_certificate(
    audit_data: str = Form(...),
    filename: str = Form(None)
):
    """
    Generate a PDF certificate from audit results.

    Args:
        audit_data: JSON string containing audit results
        filename: Optional filename for the certificate

    Returns:
        PDF file response
    """
    try:
        # Parse audit data
        if isinstance(audit_data, str):
            report = json.loads(audit_data)
        else:
            report = audit_data

        # Generate certificate
        file_id = str(uuid.uuid4())
        cert_filename = filename or f"TrustCode_Certificate_{file_id}.pdf"
        cert_path = CERT_DIR / cert_filename

        generator = PDFCertificateGenerator(report)
        generator.generate(str(cert_path))

        return FileResponse(
            path=str(cert_path),
            filename=cert_filename,
            media_type="application/pdf"
        )

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON data")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Certificate generation failed: {str(e)}")


@app.get("/api/sample-results")
async def get_sample_results():
    """Return pre-generated sample audit results for demo purposes."""
    sample_path = Path(__file__).parent / "sample_audit_results.json"

    if not sample_path.exists():
        raise HTTPException(status_code=404, detail="Sample results not available")

    with open(sample_path, 'r') as f:
        return json.load(f)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=True
    )
