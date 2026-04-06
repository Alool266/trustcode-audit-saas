import { NextRequest, NextResponse } from 'next/server';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';

const BACKEND_API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const file = formData.get('file') as File;
    
    if (!file) {
      return NextResponse.json(
        { error: 'No file provided' },
        { status: 400 }
      );
    }

    // If backend API is configured, use it
    if (BACKEND_API_URL && BACKEND_API_URL !== 'http://localhost:8000') {
      const formDataToSend = new FormData();
      formDataToSend.append('file', file, file.name);

      const response = await fetch(`${BACKEND_API_URL}/api/audit`, {
        method: 'POST',
        body: formDataToSend,
      });

      if (!response.ok) {
        const error = await response.json();
        return NextResponse.json(
          { error: error.detail || 'Audit failed' },
          { status: response.status }
        );
      }

      const data = await response.json();
      return NextResponse.json(data);
    }

    // Fallback: Run audit engine locally (for development)
    const bytes = await file.arrayBuffer();
    const buffer = Buffer.from(bytes);
    
    const tempDir = path.join(process.cwd(), 'temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    
    const tempFilePath = path.join(tempDir, file.name);
    fs.writeFileSync(tempFilePath, buffer);

    const auditEnginePath = path.join(
      process.cwd(),
      '..',
      'backend',
      'audit_engine.py'
    );
    
    const auditOutputPath = path.join(tempDir, 'audit_results.json');

    return new Promise((resolve) => {
      const pythonProcess = spawn('python', [
        auditEnginePath,
        tempFilePath,
        auditOutputPath
      ]);

      let stdout = '';
      let stderr = '';

      pythonProcess.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      pythonProcess.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      pythonProcess.on('close', (code) => {
        if (code === 0 && fs.existsSync(auditOutputPath)) {
          const auditData = JSON.parse(fs.readFileSync(auditOutputPath, 'utf-8'));
          
          // Cleanup temp files
          fs.unlinkSync(tempFilePath);
          fs.unlinkSync(auditOutputPath);
          
          resolve(NextResponse.json(auditData));
        } else {
          resolve(NextResponse.json(
            { error: 'Audit failed', details: stderr },
            { status: 500 }
          ));
        }
      });
    });

  } catch (error) {
    console.error('Audit error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}