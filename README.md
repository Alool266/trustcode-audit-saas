# TrustCode AI Audit SaaS

AI-powered code auditing platform that detects hallucinations, security vulnerabilities, and code quality issues. Generates professional compliance certificates.

## Features

- **AST-Based Static Analysis**: Deep Python code analysis using Abstract Syntax Trees
- **AI Hallucination Detection**: Identifies non-existent APIs and methods
- **Security Scanning**: Detects eval usage, hardcoded secrets, and risky patterns
- **TrustScore Calculation**: Comprehensive scoring system (0-100)
- **Professional Certificates**: PDF generation with corporate branding
- **Modern Web UI**: Fintech Calm design with glassmorphism effects

## Tech Stack

**Frontend:**
- Next.js 14 (App Router)
- TypeScript
- Tailwind CSS
- Framer Motion
- Vercel-ready

**Backend:**
- FastAPI
- Python 3.11
- ReportLab (PDF generation)
- Uvicorn (ASGI server)

## Project Structure

```
trustcode-audit-saas/
├── frontend/           # Next.js web application
│   ├── app/
│   │   ├── api/       # API routes (audit, generate-certificate, sample-results)
│   │   ├── globals.css
│   │   ├── layout.tsx
│   │   └── page.tsx   # Main UI
│   ├── Dockerfile
│   ├── vercel.json
│   ├── package.json
│   └── .env.example
├── backend/            # FastAPI server
│   ├── main.py        # API endpoints
│   ├── audit_engine.py # Core analysis engine
│   ├── generate_certificate_pdf.py # PDF generator
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── Procfile
│   └── sample_audit_results.json
├── docker-compose.yml  # Local development orchestration
└── README.md
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

### Backend (FastAPI)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/audit` | Upload Python file for analysis |
| POST | `/api/generate-certificate` | Generate PDF certificate |
| GET | `/api/sample-results` | Get demo audit results |

### Frontend (Next.js API Routes)

The frontend provides proxy endpoints that either:
- Forward requests to the backend API (if `NEXT_PUBLIC_API_URL` is set)
- Execute Python scripts locally (for development without backend)

## Deployment

### Vercel (Frontend)

1. Push code to GitHub
2. Import repository in Vercel
3. Set environment variable: `NEXT_PUBLIC_API_URL` to your backend URL
4. Deploy

### Railway/Heroku (Backend)

1. Push code to GitHub
2. Import repository in Railway or Heroku
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Deploy

### Docker (Production)

```bash
# Build and run with docker-compose
docker-compose -f docker-compose.yml up -d

# Or build individually
docker build -t trustcode-frontend ./frontend
docker build -t trustcode-backend ./backend
```

## Configuration

### Backend Settings

- `PORT`: Server port (default: 8000)
- Upload and certificate directories are created automatically

### Frontend Settings

- `NEXT_PUBLIC_API_URL`: Backend API URL (required for production)

## Certificate Generation

Certificates include:
- TrustScore and audit summary
- Detailed findings table with severity levels
- PhD-level recommendations
- Professional branding with creator credit
- Footer with timestamp and logo

## License

Proprietary - All rights reserved

## Author

Created by Ali Hasan
https://alool266.github.io/portfolio-website/