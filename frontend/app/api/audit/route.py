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

from fastapi import FastAPI, File, UploadFile, HTTPException, Form, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum

# Import the new modular architecture
from analyzers.language_router import LanguageRouter
from analyzers.false_positive_reducer import FalsePositiveReducer

app = FastAPI(title="TrustCode AI Audit API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the router and reducer
router = LanguageRouter()
reducer = FalsePositiveReducer()


@app.post("/api/audit")
async def audit_code(request: Request):
    """
    Analyze uploaded code file(s).
    Supports both single file uploads and zip archives (future).
    """
    try:
        # Get the uploaded file
        form_data = await request.form()
        file = form_data.get('file')
        
        if not file:
            raise HTTPException(status_code=400, detail="No file provided")
        
        if not hasattr(file, 'filename') or not file.filename:
            raise HTTPException(status_code=400, detail="Invalid file")
        
        filename = file.filename
        
        # Check if it's a zip file (future support)
        if filename.endswith('.zip'):
            # TODO: Implement zip handling in Sprint 2
            raise HTTPException(status_code=501, detail="Zip upload not yet supported")
        
        # For now, only Python files
        if not filename.endswith('.py'):
            raise HTTPException(status_code=400, detail="Only Python (.py) files are supported")
        
        # Use platform-appropriate temp directory
        if os.environ.get('VERCEL'):
            upload_dir = Path("/tmp/uploads")
        else:
            upload_dir = Path(tempfile.gettempdir()) / "trustcode_audit_uploads"
        
        upload_dir.mkdir(exist_ok=True)
        
        file_id = str(uuid.uuid4())
        file_path = upload_dir / f"{file_id}.py"
        
        # Read file content
        content = await file.read()
        with open(file_path, 'wb') as f:
            f.write(content)
        
        # Read as text
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        # Analyze using the language router
        result = router.analyze_file(source_code, str(file_path))
        
        # Apply false positive reduction
        if 'Findings' in result:
            result['Findings'] = reducer.filter_findings(result['Findings'], str(file_path))
            result['AuditMetadata']['total_findings'] = len(result['Findings'])
            # Recalculate trust score after filtering
            from analyzers.python_analyzer import PythonAnalyzer
            analyzer = PythonAnalyzer()
            result['TrustScore'] = analyzer.calculate_trust_score(result['Findings'])
            result['PhD_Level_Recommendation'] = analyzer.generate_recommendation(result['Findings'])
        
        return JSONResponse(content=result)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")
    finally:
        if 'file_path' in locals() and file_path.exists():
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


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "TrustCode AI Audit API"}


# Wrap for Vercel serverless
handler = Mangum(app)
