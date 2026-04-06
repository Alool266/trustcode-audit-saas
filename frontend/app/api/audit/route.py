"""
Vercel Python serverless function for code audit.
This runs within the Next.js frontend project.
"""

import os
import sys
import json
import uuid
import tempfile
from pathlib import Path

# Add current directory and frontend root to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from audit_engine import AuditEngine

app = FastAPI(title="TrustCode AI Audit API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/audit")
async def audit_code(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith('.py'):
        raise HTTPException(status_code=400, detail="Only Python (.py) files are supported")

    # Use platform-appropriate temp directory
    if os.environ.get('VERCEL'):
        upload_dir = Path("/tmp/uploads")
    else:
        upload_dir = Path(tempfile.gettempdir()) / "trustcode_audit_uploads"

    upload_dir.mkdir(exist_ok=True)

    file_id = str(uuid.uuid4())
    file_path = upload_dir / f"{file_id}.py"

    try:
        content = await file.read()
        with open(file_path, 'wb') as f:
            f.write(content)

        engine = AuditEngine(str(file_path))
        engine.load_file()
        engine.analyze()
        report = engine.generate_report()

        return JSONResponse(content=report)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")
    finally:
        if file_path.exists():
            try:
                file_path.unlink()
            except:
                pass


@app.get("/api/sample-results")
async def get_sample_results():
    """Return sample audit results for demo purposes."""
    sample_path = Path(__file__).parent / "sample_audit_results.json"

    if not sample_path.exists():
        raise HTTPException(status_code=404, detail="Sample results not available")

    with open(sample_path, 'r') as f:
        return json.load(f)


# Wrap for Vercel serverless
handler = Mangum(app)
