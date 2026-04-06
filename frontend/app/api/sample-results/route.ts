import { NextResponse } from 'next/server';

const BACKEND_API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export async function GET() {
  try {
    // If backend API is configured, use it
    if (BACKEND_API_URL && BACKEND_API_URL !== 'http://localhost:8000') {
      const response = await fetch(`${BACKEND_API_URL}/api/sample-results`);
      
      if (!response.ok) {
        const error = await response.json();
        return NextResponse.json(
          { error: error.detail || 'Sample results not available' },
          { status: response.status }
        );
      }

      const data = await response.json();
      return NextResponse.json(data);
    }

    // Fallback: Return demo data for local development
    const demoData = {
      TrustScore: 30,
      Findings: [
        {
          category: "Unknown API",
          severity: "high",
          message: "Potentially hallucinated method 'read_csv_fast' in pandas. Did you mean: read_csv?",
          line: 13,
          snippet: "def load_data_fast():\n    \"\"\"This uses a hallucinated pandas method.\"\"\"\n>>>     data = pd.read_csv_fast('data.csv')  # Should be read_csv\n    return data",
          recommendation: "Verify the pandas API documentation for correct method names."
        },
        {
          category: "Security",
          severity: "critical",
          message: "Dangerous function 'eval' used - code injection risk",
          line: 65,
          snippet: "def process_user_input(user_input):\n    \"\"\"Dangerous eval usage.\"\"\"\n>>>     result = eval(user_input)  # CRITICAL security issue\n    return result",
          recommendation: "Avoid eval/exec. Use safer alternatives like ast.literal_eval() or specific APIs."
        }
      ],
      PhD_Level_Recommendation: "CRITICAL INTERVENTION REQUIRED: 1 critical issue(s) detected. Immediate refactoring is essential before production deployment. Focus on security vulnerabilities and API correctness.",
      AuditMetadata: {
        file: "sample_code.py",
        audit_date: new Date().toISOString(),
        engine_version: "1.0.0",
        total_findings: 2
      }
    };
    return NextResponse.json(demoData);
  } catch (error) {
    console.error('Error loading sample results:', error);
    return NextResponse.json(
      { error: 'Sample results not available' },
      { status: 404 }
    );
  }
}