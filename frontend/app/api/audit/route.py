"""
Vercel Python serverless function for code audit.
This runs within the Next.js frontend project.
"""

import os
import sys
import json
import uuid
import tempfile
import zipfile
import io
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
from custom_rule_engine import CustomRuleEngine, DEFAULT_RULES_DIR

app = FastAPI(title="TrustCode AI Audit API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the router, reducer, and custom rule engine
router = LanguageRouter()
reducer = FalsePositiveReducer()
rule_engine = CustomRuleEngine(DEFAULT_RULES_DIR)


@app.post("/api/audit")
async def audit_code(request: Request):
    """
    Analyze uploaded code file(s).
    Supports both single file uploads and zip archives.
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
        
        # Check if it's a zip file
        if filename.endswith('.zip'):
            return await audit_zip(file)
        
        # Check if the file extension is supported
        supported_extensions = router.get_supported_extensions()
        if not any(filename.endswith(ext) for ext in supported_extensions):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type. Supported extensions: {', '.join(supported_extensions)}"
            )
        
        # Use platform-appropriate temp directory
        if os.environ.get('VERCEL'):
            upload_dir = Path("/tmp/uploads")
        else:
            upload_dir = Path(tempfile.gettempdir()) / "trustcode_audit_uploads"
        
        upload_dir.mkdir(exist_ok=True)
        
        file_id = str(uuid.uuid4())
        # Preserve original file extension
        file_extension = Path(filename).suffix
        file_path = upload_dir / f"{file_id}{file_extension}"
        
        # Read file content
        content = await file.read()
        with open(file_path, 'wb') as f:
            f.write(content)
        
        # Read as text
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        # Analyze using the language router
        result = router.analyze_file(source_code, str(file_path))
        
        # Apply custom rules
        language = router.get_language_name(str(file_path))
        custom_findings = rule_engine.apply_all_rules(source_code, language, file_path=str(file_path))
        
        # Merge custom rule findings with existing findings
        if 'Findings' in result:
            result['Findings'].extend(custom_findings)
            # Apply false positive reduction
            result['Findings'] = reducer.filter_findings(result['Findings'], str(file_path))
            result['AuditMetadata']['total_findings'] = len(result['Findings'])
            # Recalculate trust score after filtering using the appropriate analyzer
            analyzer = router.get_analyzer(str(file_path))
            if analyzer:
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


async def audit_zip(file):
    """Analyze all supported files in a zip archive."""
    supported_extensions = router.get_supported_extensions()
    
    # Use platform-appropriate temp directory
    if os.environ.get('VERCEL'):
        upload_dir = Path("/tmp/uploads")
    else:
        upload_dir = Path(tempfile.gettempdir()) / "trustcode_audit_uploads"
    
    upload_dir.mkdir(exist_ok=True)
    
    # Read zip file content
    zip_content = await file.read()
    zip_file = zipfile.ZipFile(io.BytesIO(zip_content))
    
    all_findings = []
    file_results = []
    total_files = 0
    scanned_files = 0
    
    # Get list of files in zip
    file_list = [f for f in zip_file.namelist() if not f.startswith('__MACOSX') and not f.startswith('.')]
    total_files = len([f for f in file_list if any(f.endswith(ext) for ext in supported_extensions)])
    
    for file_name in file_list:
        # Skip directories
        if file_name.endswith('/'):
            continue
        
        # Check if file has supported extension
        if not any(file_name.endswith(ext) for ext in supported_extensions):
            continue
        
        scanned_files += 1
        
        try:
            # Read file content from zip
            source_code = zip_file.read(file_name).decode('utf-8', errors='ignore')
            
            # Create temp file for analysis
            file_id = str(uuid.uuid4())
            file_extension = Path(file_name).suffix
            temp_path = upload_dir / f"{file_id}{file_extension}"
            
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(source_code)
            
            # Analyze using the language router
            result = router.analyze_file(source_code, file_name)
            
            # Apply custom rules
            language = router.get_language_name(file_name)
            custom_findings = rule_engine.apply_all_rules(source_code, language, file_path=file_name)
            
            # Merge custom rule findings with existing findings
            if 'Findings' in result:
                result['Findings'].extend(custom_findings)
                # Apply false positive reduction
                result['Findings'] = reducer.filter_findings(result['Findings'], file_name)
                result['AuditMetadata']['total_findings'] = len(result['Findings'])
                # Recalculate trust score after filtering using the appropriate analyzer
                analyzer = router.get_analyzer(file_name)
                if analyzer:
                    result['TrustScore'] = analyzer.calculate_trust_score(result['Findings'])
                    result['PhD_Level_Recommendation'] = analyzer.generate_recommendation(result['Findings'])
            
            # Add file path to result
            result['file'] = file_name
            file_results.append(result)
            
            # Collect all findings
            all_findings.extend(result.get('Findings', []))
            
            # Clean up temp file
            try:
                temp_path.unlink()
            except:
                pass
                
        except Exception as e:
            file_results.append({
                'file': file_name,
                'error': str(e),
                'TrustScore': 0,
                'Findings': []
            })
    
    # Calculate overall trust score
    if file_results:
        avg_score = sum(r.get('TrustScore', 0) for r in file_results) / len(file_results)
        overall_trust_score = int(avg_score)
    else:
        overall_trust_score = 0
    
    # Generate overall recommendation
    if all_findings:
        critical_count = sum(1 for f in all_findings if f.get('severity', '').lower() == 'critical')
        high_count = sum(1 for f in all_findings if f.get('severity', '').lower() == 'high')
        
        if critical_count > 0:
            recommendation = f"CRITICAL: {critical_count} critical issue(s) found across {scanned_files} files. Immediate attention required."
        elif high_count > 0:
            recommendation = f"HIGH PRIORITY: {high_count} high-severity issue(s) require attention across {scanned_files} files."
        else:
            recommendation = f"MODERATE: {len(all_findings)} issues found across {scanned_files} files. Review and address as needed."
    else:
        recommendation = "EXCELLENT: No significant issues detected across all scanned files."
    
    return JSONResponse(content={
        "TrustScore": overall_trust_score,
        "TotalFiles": total_files,
        "ScannedFiles": scanned_files,
        "TotalFindings": len(all_findings),
        "Recommendation": recommendation,
        "FileResults": file_results
    })


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
