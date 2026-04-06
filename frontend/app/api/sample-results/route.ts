import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

export async function GET(): Promise<Response> {
  try {
    // Look for sample data in the frontend directory
    const samplePath = path.join(process.cwd(), 'sample_audit_results.json');
    
    if (!fs.existsSync(samplePath)) {
      // Try alternative location
      const altPath = path.join(process.cwd(), '..', 'sample_audit_results.json');
      if (!fs.existsSync(altPath)) {
        throw new Error('Sample results not found');
      }
      // Read from alternative location
      const content = fs.readFileSync(altPath, 'utf-8');
      return NextResponse.json(JSON.parse(content));
    }

    const content = fs.readFileSync(samplePath, 'utf-8');
    return NextResponse.json(JSON.parse(content));
  } catch (error) {
    console.error('Error loading sample results:', error);
    return NextResponse.json(
      { error: 'Sample results not available' },
      { status: 404 }
    );
  }
}
