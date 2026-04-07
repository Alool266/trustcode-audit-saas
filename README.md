# TrustCode AI Audit SaaS

AI-powered code auditing platform that detects hallucinations, security vulnerabilities, and code quality issues. Generates professional compliance certificates.

## Features

### Core Capabilities
- **Multi-Language Support**: Python, JavaScript, TypeScript, Java, Go, Rust via AST parsing and tree-sitter
- **AST-Based Static Analysis**: Deep code analysis using Abstract Syntax Trees for Python, tree-sitter for other languages
- **AI Hallucination Detection**: Identifies non-existent APIs, methods, and logic inconsistencies
- **Security Scanning**: Detects eval/exec usage, hardcoded secrets, SQL injection patterns, XSS, command injection, and more
- **Code Quality Checks**: Empty except blocks, bare except, nested loops, magic numbers, resource leaks
- **TrustScore Calculation**: Comprehensive scoring system (0-100) with CVSS-inspired severity levels
- **Project Scanning**: Upload entire codebases as ZIP files for aggregated analysis across multiple files
- **Professional Certificates**: Client-side PDF generation with TrustCode branding, Ali Hasan credit, and detailed findings
- **Interactive Dashboard**: Real-time results with severity distribution charts, category breakdown, and CVSS radial visualization
- **Custom Rule Engine**: YAML-based rule definition for organization-specific detection rules
- **False Positive Reduction**: Context-aware filtering for test files, mocks, and example code
- **Modern Web UI**: Fintech Calm dark theme with glassmorphism effects, smooth Framer Motion animations

### Advanced Features
- **File Tree View**: Navigate scanned projects with expandable file tree
- **Search & Filtering**: Filter findings by severity, category, file, and search queries
- **Visual Analytics**: Pie charts, bar charts, and radial charts for severity distribution
- **Detailed Findings Table**: Sortable, filterable table with code snippets and line numbers
- **PhD-Level Recommendations**: AI-generated remediation guidance for each finding
- **Responsive Design**: Works seamlessly on desktop and mobile devices
- **Serverless Architecture**: Python backend integrated as Vercel serverless functions for easy deployment

## Tech Stack

**Frontend:**
- Next.js 16 (App Router)
- TypeScript 5
- Tailwind CSS 4
- Framer Motion 12
- Recharts (data visualization)
- jsPDF + jsPDF-AutoTable (client-side PDF generation)

**Backend (Serverless):**
- FastAPI 0.104 (Python web framework)
- Python 3.11
- Mangum (AWS Lambda/Vercel adapter)
- Tree-sitter (multi-language AST parsing)
- PyYAML (custom rule engine)
- Uvicorn (ASGI server)

**Deployment:**
- Vercel (Frontend + Python Serverless Functions)
- Docker & Docker Compose (local development)
- GitHub (source control)

## Project Structure

```
trustcode-audit-saas/
├── frontend/                 # Next.js web application (deployed to Vercel)
│   ├── app/
│   │   ├── api/
│   │   │   ├── audit-backend/    # Python serverless function (legacy)
│   │   │   ├── generate-certificate/  # Next.js API route (stub)
│   │   │   └── sample-results/  # Next.js API route for demo data
│   │   ├── globals.css
│   │   ├── layout.tsx
│   │   └── page.tsx            # Main UI with PDF generation
│   ├── backend/                # Python serverless functions (Vercel)
│   │   ├── route.py            # Main API router for /api/audit
│   │   ├── analyzers/          # Language-specific analyzers
│   │   │   ├── base_analyzer.py
│   │   │   ├── python_analyzer.py (refactored from audit_engine.py)
│   │   │   ├── javascript_analyzer.py
│   │   │   ├── java_analyzer.py
│   │   │   ├── go_analyzer.py
│   │   │   ├── rust_analyzer.py
│   │   │   └── false_positive_reducer.py
│   │   ├── language_router.py  # Routes files to appropriate analyzer
│   │   ├── custom_rule_engine.py  # YAML-based rule engine
│   │   ├── requirements.txt
│   │   └── sample_audit_results.json
│   ├── public/
│   ├── Dockerfile
│   ├── vercel.json             # Vercel build configuration
│   ├── package.json
│   └── .env.example
├── backend/                    # Legacy separate backend (deprecated)
│   ├── main.py
│   ├── audit_engine.py
│   ├── generate_certificate_pdf.py
│   ├── requirements.txt
│   └── vercel.json
├── docker-compose.yml          # Local development orchestration
├── plans/
│   └── IMPLEMENTATION_PLAN.md  # Detailed implementation plan
├── README.md
└── .gitignore
```

## Quick Start

### Local Development

1. **Clone and setup:**
```bash
cd trustcode-audit-saas
cd frontend && npm install && cd ..
cd backend && pip install -r requirements.txt && cd ..
```

2. **Start with Docker Compose:**
```bash
docker-compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

3. **Or start manually:**

Backend:
```bash
cd backend
uvicorn main:app --reload --port 8000
```

Frontend:
```bash
cd frontend
npm run dev
```

### Environment Configuration

Create a `.env.local` file in the `frontend` directory:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

For production, set this to your deployed backend URL.

## API Endpoints

### Python Serverless Functions (Vercel)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/audit` | Upload Python file or ZIP for analysis |
| GET | `/api/sample-results` | Get demo audit results |

### Frontend (Next.js API Routes)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sample-results` | Returns sample audit results from local JSON |
| POST | `/api/generate-certificate` | Stub (PDF now generated client-side) |

### Request/Response Format

**Upload File for Audit:**
```
POST /api/audit
Content-Type: multipart/form-data
Body: { file: File }

Response: {
  TrustScore: number,
  TotalFiles: number,
  ScannedFiles: number,
  TotalFindings: number,
  Recommendation: string,
  FileResults: [...],
  AuditMetadata: {...}
}
```

## Deployment

### Vercel (Recommended - Single Project)

The entire application is deployed as a single Next.js project with Python serverless functions:

1. Push code to GitHub
2. Import repository in Vercel
3. **No environment variables required** (Python backend is integrated)
4. Deploy

**Live Demo:** [https://frontend-six-psi-78.vercel.app](https://frontend-six-psi-78.vercel.app)

> **Note:** The Python audit backend runs as Vercel serverless functions (`/api/audit`, `/api/sample-results`) within the frontend project. This eliminates the need for separate backend deployment and simplifies scaling.

### Docker (Local Development/Production)

```bash
# Build and run with docker-compose
docker-compose -f docker-compose.yml up -d

# Or build individually
docker build -t trustcode-frontend ./frontend
docker build -t trustcode-backend ./backend
```

### Local Development

```bash
# Frontend
cd frontend
npm install
npm run dev

# Backend (in separate terminal)
cd frontend/backend
pip install -r requirements.txt
# The backend is automatically called by the frontend via /api/audit
```

## Configuration

### Frontend Settings

- `NEXT_PUBLIC_API_URL`: Optional. If set, frontend will use external API instead of local Python serverless function. For local development without Python, this can point to any compatible API.
  - Default: Uses internal `/api/audit` route (Python serverless function)
  - Example: `NEXT_PUBLIC_API_URL=http://localhost:8000` (for separate backend)

### Python Backend Settings

The Python serverless function runs within Vercel and uses:
- `/tmp` directory for temporary file storage (Vercel's ephemeral filesystem)
- Automatic scaling based on request volume
- No persistent storage (results are returned directly in response)

## Certificate Generation

Certificates include:
- TrustScore and audit summary
- Detailed findings table with severity levels
- PhD-level recommendations
- Professional branding with creator credit
- Footer with timestamp and logo

## Current Implementation Status

### ✅ Completed Features

**Multi-Language Support (Sprint 1-3)**
- Python AST analysis (via `audit_engine.py`)
- JavaScript/TypeScript analysis (tree-sitter)
- Java, Go, Rust analyzers
- Language router for automatic file type detection

**Project Scanning (Sprint 4)**
- ZIP file upload support
- Multi-file analysis with aggregation
- File tree view in UI
- Intelligent file filtering (ignores node_modules, .git, etc.)

**Enhanced Reports (Sprint 5)**
- CVSS-inspired severity scoring (0-10)
- Visual charts: Pie (severity distribution), Bar (category breakdown), Radial (CVSS)
- Detailed findings with code snippets
- PhD-level remediation recommendations
- TrustScore calculation (0-100)

**Custom Rules (Sprint 6)**
- YAML-based rule engine
- Example rules for security API keys and hardcoded secrets
- Extensible rule format for custom patterns

**Frontend UI (Sprint 7)**
- Fintech Calm dark theme with glassmorphism
- Framer Motion animations
- Search and filter by severity/category/file
- Client-side PDF generation (jsPDF)
- Responsive design

**Deployment (Sprint 8)**
- Vercel serverless functions integration
- Single-project deployment (frontend + Python backend)
- Docker support for local development
- Production-ready on https://frontend-six-psi-78.vercel.app

### 🚀 Future Enhancements

**Security Analysis**
- **Taint/Data Flow Analysis**: Track user input propagation to detect SQL injection, XSS, command injection
- **CWE Mapping**: Map findings to Common Weakness Enumeration IDs
- **Dependency Scanning**: Analyze requirements.txt, package.json for vulnerable dependencies
- **Secrets Detection**: Advanced pattern matching for API keys, passwords, certificates

**Performance & Scale**
- **Parallel Processing**: Analyze multiple files concurrently within Vercel's timeout limits
- **Incremental Scanning**: Cache results and only re-scan changed files
- **Streaming Responses**: Stream results for large projects to avoid timeouts
- **Background Processing**: Queue-based processing for very large codebases

**User Experience**
- **Historical Tracking**: Save audit history and show trend graphs over time
- **Git Integration**: Connect to GitHub/GitLab for automated PR scanning
- **Code Viewer**: Interactive code viewer with syntax highlighting and inline issue markers
- **Export Options**: JSON, CSV, HTML, Markdown exports in addition to PDF
- **Team Features**: Multi-user support, shared projects, role-based access

**Enterprise Features**
- **Authentication**: JWT-based login with email/password or OAuth (Google, GitHub)
- **Database**: PostgreSQL for storing audit history, user data, custom rules
- **Rate Limiting**: API throttling per user/IP
- **Webhooks**: Notify external systems (Slack, Teams, CI/CD) on audit completion
- **Audit Trail**: Complete log of all actions for compliance

**Advanced Analytics**
- **Risk Heatmap**: Visualize risk distribution across the codebase
- **Remediation Workflow**: Assign findings to team members, track fix progress
- **Compliance Reports**: Generate reports for SOC2, ISO27001, GDPR requirements
- **Benchmarking**: Compare your code quality against industry standards

**AI-Powered Features**
- **Smart Fix Suggestions**: AI-generated code fixes for each finding
- **Code Review Automation**: Automatically review PRs and post comments
- **Learning Mode**: Adapt to your codebase and reduce false positives over time
- **Natural Language Queries**: Ask questions about your audit results in plain English

**Certificate Enhancements**
- **Verification Portal**: Online page to verify certificate authenticity using unique IDs
- **QR Codes**: Embed scannable QR codes linking to verification pages
- **Custom Templates**: Multiple certificate designs (corporate, academic, startup)
- **Digital Signatures**: Cryptographically signed certificates for tamper-proof verification
- **Branding**: Upload custom logos, colors, and company information

**Monetization**
- **Usage-Based Pricing**: Pay per audit or per line scanned
- **Subscription Tiers**: Free (5 audits/mo), Pro ($29/mo), Enterprise (custom)
- **On-Premise Deployment**: Self-hosted version for air-gapped environments
- **White Label**: Rebrand the entire platform for agencies and consultants

## License

Proprietary - All rights reserved

## Author

Created by Ali Hasan
https://alool266.github.io/portfolio-website/