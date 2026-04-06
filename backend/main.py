"""
Vercel serverless handler for TrustCode AI Audit SaaS.
"""

import os
import sys
import json
import uuid
from pathlib import Path

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from audit_engine import AuditEngine

app = FastAPI(
    title="TrustCode AI Audit API",
    description="Backend API for code auditing and certificate generation",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("/tmp/uploads")
CERT_DIR = Path("/tmp/certificates")
UPLOAD_DIR.mkdir(exist_ok=True)
CERT_DIR.mkdir(exist_ok=True)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "TrustCode AI Audit Backend"}


@app.post("/api/audit")
async def audit_code(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith('.py'):
        raise HTTPException(status_code=400, detail="Only Python (.py) files are supported")

    file_id = str(uuid.uuid4())
    file_path = UPLOAD_DIR / f"{file_id}.py"

    try:
        content = await file.read()
        with open(file_path, 'wb') as f:
            f.write(content)

        engine = AuditEngine(str(file_path))
        engine.load_file()
        engine.analyze()
        report = engine.generate_report()

        report_path = UPLOAD_DIR / f"{file_id}_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        return JSONResponse(content=report)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")
    finally:
        if file_path.exists():
            file_path.unlink()


@app.post("/api/generate-certificate")
async def generate_certificate(
    audit_data: str = Form(...),
    filename: str = Form(None)
):
    """
    Generate a PDF certificate from audit results.
    Note: This endpoint is deprecated. Certificate generation now happens client-side.
    Returns the audit data for frontend to use.
    """
    try:
        if isinstance(audit_data, str):
            report = json.loads(audit_data)
        else:
            report = audit_data
        
        # Return the audit data - frontend will generate PDF
        return JSONResponse(content={
            "success": True,
            "message": "Audit data received, generate certificate client-side",
            "audit_data": report
        })

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON data")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Certificate generation failed: {str(e)}")


@app.get("/api/sample-results")
async def get_sample_results():
    sample_path = Path(__file__).parent / "sample_audit_results.json"

    if not sample_path.exists():
        raise HTTPException(status_code=404, detail="Sample results not available")

    with open(sample_path, 'r') as f:
        return json.load(f)


# Wrap for Vercel serverless
handler = Mangum(app)
