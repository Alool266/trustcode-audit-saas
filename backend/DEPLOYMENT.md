# TrustCode AI - Deployment Guide

## Overview

TrustCode AI is a comprehensive code auditing tool that detects AI hallucinations, logic risks, and security vulnerabilities in Python code. It generates professional compliance certificates in PDF format.

**Created by:** Ali Hasan  
**Portfolio:** https://alool266.github.io/portfolio-website/

## Project Structure

```
sentinel-zero/
├── python-ai-agent/
│   ├── src/
│   │   ├── audit_engine.py              # AST-based static analysis engine
│   │   ├── generate_certificate.py      # Word certificate generator
│   │   ├── generate_certificate_pdf.py  # PDF certificate generator
│   │   ├── sample_code.py               # Sample code with deliberate hallucinations
│   │   └── audit_results.json           # Generated audit results
│   └── requirements.txt                 # Python dependencies

trustcode-ui/
├── app/
│   ├── page.tsx                         # Main UI component
│   ├── globals.css                      # Fintech Calm dark theme
│   └── api/
│       ├── audit/route.ts               # Audit API endpoint
│       ├── generate-certificate/route.ts # Certificate generation API
│       └── sample-results/route.ts      # Sample results API
└── package.json                         # Node.js dependencies
```

## Prerequisites

- Python 3.10+
- Node.js 18+
- npm or yarn

## Local Development

### 1. Install Python Dependencies

```bash
cd sentinel-zero/python-ai-agent
pip install -r requirements.txt
pip install reportlab  # For PDF generation
```

### 2. Install Node.js Dependencies

```bash
cd trustcode-ui
npm install
```

### 3. Run the Audit Engine

```bash
cd sentinel-zero/python-ai-agent/src
python audit_engine.py sample_code.py audit_results.json
```

### 4. Generate PDF Certificate

```bash
python generate_certificate_pdf.py audit_results.json TrustCode_Certificate.pdf
```

### 5. Start the Web UI

```bash
cd trustcode-ui
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Deployment to Vercel

### 1. Push to GitHub

```bash
cd trustcode-ui
git init
git add .
git commit -m "Initial commit"
git remote add origin <your-repo-url>
git push -u origin main
```

### 2. Deploy on Vercel

1. Go to [vercel.com](https://vercel.com)
2. Click "New Project"
3. Import your GitHub repository
4. Configure build settings:
   - **Framework Preset:** Next.js
   - **Root Directory:** trustcode-ui
   - **Build Command:** `npm run build`
   - **Output Directory:** `.next`
5. Click "Deploy"

### 3. Configure Python Backend

For production, you'll need to deploy the Python audit engine separately. Options:

#### Option A: Serverless Functions (Vercel)

The API routes in `trustcode-ui/app/api/` already handle the Python execution. You just need to ensure Python is available in your deployment environment.

#### Option B: Separate Python Server

Deploy the Python audit engine as a separate service (e.g., on Render, Railway, or AWS Lambda) and update the API routes to call the external endpoint.

## Environment Variables

Create a `.env.local` file in the `trustcode-ui` directory:

```env
# Path to the audit engine (optional, defaults to relative path)
AUDIT_ENGINE_PATH=/path/to/audit_engine.py

# Path to the certificate generator (optional)
CERTIFICATE_GENERATOR_PATH=/path/to/generate_certificate_pdf.py
```

## API Endpoints

### POST /api/audit

Upload a Python file for auditing.

**Request:**
- Content-Type: `multipart/form-data`
- Body: `FormData` with `file` field

**Response:**
```json
{
  "TrustScore": 30,
  "Findings": [...],
  "PhD_Level_Recommendation": "...",
  "AuditMetadata": {...}
}
```

### POST /api/generate-certificate

Generate a PDF certificate from audit results.

**Request:**
- Content-Type: `application/json`
- Body: `{ "auditJson": "{...}" }`

**Response:**
- Content-Type: `application/pdf`
- File: `TrustCode_Certificate.pdf`

## Features

### Audit Engine
- **AST Analysis:** Parses Python code into Abstract Syntax Tree
- **Unknown API Detection:** Identifies hallucinated library methods
- **Silent Logic Failures:** Flags empty except blocks and bare except clauses
- **Performance Risks:** Detects O(n²) nested loops
- **Security:** Flags hardcoded secrets and eval() usage
- **Code Quality:** Identifies magic numbers

### Certificate Generator
- **Professional PDF:** Corporate design with TrustCode branding
- **Creator Credit:** Includes Ali Hasan's name and portfolio link
- **TrustScore:** Visual score indicator with color coding
- **Findings Table:** Detailed list of all issues found
- **PhD Recommendation:** Comprehensive improvement suggestions

### Web UI
- **Fintech Calm Design:** Dark theme with cyan accents
- **Glassmorphism:** Modern frosted glass effect on upload box
- **Scanning Animation:** Progress bar with step indicators
- **Smooth Transitions:** Framer Motion animations between states
- **Responsive:** Works on desktop and mobile

## Customization

### Changing Colors

Edit `trustcode-ui/app/globals.css`:

```css
:root {
  --background: #020617;  /* Deep Slate */
  --accent: #22d3ee;      /* Cyan */
  --danger: #f43f5e;      /* Rose */
  --success: #10b981;     /* Emerald */
}
```

### Adding New API Checks

Edit `sentinel-zero/python-ai-agent/src/audit_engine.py`:

```python
KNOWN_APIS = {
    'pandas': {
        'read_csv': [...],
        'read_excel': [...],
        # Add new methods here
    },
    # Add new libraries here
}
```

## Troubleshooting

### Audit Engine Not Found

Ensure the Python path is correct in the API routes:

```typescript
const auditEnginePath = path.join(
  process.cwd(),
  '..',
  'sentinel-zero',
  'python-ai-agent',
  'src',
  'audit_engine.py'
);
```

### Certificate Generation Fails

Check that `reportlab` is installed:

```bash
pip install reportlab
```

### UI Not Loading

Ensure all Node.js dependencies are installed:

```bash
cd trustcode-ui
npm install
```

## License

This project is created by Ali Hasan. All rights reserved.

**Portfolio:** https://alool266.github.io/portfolio-website/