import { NextRequest, NextResponse } from 'next/server';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';

const BACKEND_API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const auditJson = body.auditJson as string;
    
    if (!auditJson) {
      return NextResponse.json(
        { error: 'No audit data provided' },
        { status: 400 }
      );
    }

    // If backend API is configured, use it
    if (BACKEND_API_URL && BACKEND_API_URL !== 'http://localhost:8000') {
      const response = await fetch(`${BACKEND_API_URL}/api/generate-certificate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          audit_data: auditJson,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        return NextResponse.json(
          { error: error.detail || 'Certificate generation failed' },
          { status: response.status }
        );
      }

      const buffer = Buffer.from(await response.arrayBuffer());
      
      return new NextResponse(buffer, {
        status: 200,
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': 'attachment; filename="TrustCode_Certificate.pdf"',
        },
      });
    }

    // Fallback: Run certificate generator locally (for development)
    const tempDir = path.join(process.cwd(), 'temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    
    const auditInputPath = path.join(tempDir, 'audit_results.json');
    const certificateOutputPath = path.join(tempDir, 'TrustCode_Certificate.pdf');
    
    fs.writeFileSync(auditInputPath, auditJson);

    const certGenPath = path.join(
      process.cwd(),
      '..',
      'backend',
      'generate_certificate_pdf.py'
    );
    
    return new Promise((resolve) => {
      const pythonProcess = spawn('python', [
        certGenPath,
        auditInputPath,
        certificateOutputPath
      ]);

      let stderr = '';

      pythonProcess.stdout.on('data', (data) => {
        console.log('Certificate generator:', data.toString());
      });

      pythonProcess.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      pythonProcess.on('close', (code) => {
        if (code === 0 && fs.existsSync(certificateOutputPath)) {
          const fileBuffer = fs.readFileSync(certificateOutputPath);
          
          // Cleanup temp files
          fs.unlinkSync(auditInputPath);
          fs.unlinkSync(certificateOutputPath);
          
          resolve(
            new NextResponse(fileBuffer, {
              status: 200,
              headers: {
                'Content-Type': 'application/pdf',
                'Content-Disposition': 'attachment; filename="TrustCode_Certificate.pdf"',
              },
            })
          );
        } else {
          resolve(NextResponse.json(
            { error: 'Certificate generation failed', details: stderr },
            { status: 500 }
          ));
        }
      });
    });

  } catch (error) {
    console.error('Certificate generation error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}