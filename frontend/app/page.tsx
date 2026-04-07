'use client';

import { useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, RadialBarChart, RadialBar } from 'recharts';

interface AuditResult {
  TrustScore: number;
  Findings: Array<{
    category: string;
    severity: string;
    message: string;
    line: number;
    snippet: string;
    recommendation: string;
  }>;
  PhD_Level_Recommendation: string;
  AuditMetadata: {
    file: string;
    audit_date: string;
    engine_version: string;
    total_findings: number;
  };
  // Project scan results
  TotalFiles?: number;
  ScannedFiles?: number;
  FileResults?: Array<{
    file: string;
    TrustScore: number;
    Findings: Array<{
      category: string;
      severity: string;
      message: string;
      line: number;
      snippet: string;
      recommendation: string;
    }>;
    PhD_Level_Recommendation: string;
    AuditMetadata: {
      file: string;
      total_findings: number;
    };
    error?: string;
  }>;
}

export default function Home() {
  const [isDragging, setIsDragging] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(new Set());

  const handleFileUpload = async (file: File) => {
    if (!file.name.endsWith('.py') && !file.name.endsWith('.zip')) {
      setError('Please upload a Python file (.py) or a project archive (.zip)');
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setError(null);
    setResult(null);

    // Simulate scanning progress
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return 90;
        }
        return prev + 10;
      });
    }, 300);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/audit', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.error || `Audit failed with status ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
      setScanProgress(100);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Audit failed';
      setError(`Audit failed: ${errorMessage}. Please try again.`);
      console.error('Audit error:', err);
    } finally {
      clearInterval(progressInterval);
      setTimeout(() => setIsScanning(false), 500);
    }
  };

  const onDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    
    const files = e.dataTransfer.files;
    if (files && files[0]) {
      handleFileUpload(files[0]);
    }
  }, []);

  const onDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const onDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const onFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files[0]) {
      handleFileUpload(files[0]);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400';
    if (score >= 60) return 'text-cyan-400';
    if (score >= 40) return 'text-amber-400';
    return 'text-rose-400';
  };

  const getScoreLabel = (score: number) => {
    if (score >= 80) return 'EXCELLENT';
    if (score >= 60) return 'GOOD';
    if (score >= 40) return 'MODERATE';
    return 'CRITICAL';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-rose-500';
      case 'high': return 'bg-rose-400';
      case 'medium': return 'bg-amber-400';
      case 'low': return 'bg-cyan-400';
      default: return 'bg-slate-400';
    }
  };

  const generateCertificate = (auditResult: AuditResult) => {
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4'
    });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 20;
    let y = 20;

    // Background
    doc.setFillColor(2, 6, 23); // #020617
    doc.rect(0, 0, pageWidth, pageHeight, 'F');

    // Top border line
    doc.setDrawColor(6, 182, 212); // cyan-500
    doc.setLineWidth(1);
    doc.line(margin, y, pageWidth - margin, y);
    y += 15;

    // Header - TrustCode AI
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(28);
    doc.setFont('helvetica', 'bold');
    doc.text('TrustCode AI', pageWidth / 2, y, { align: 'center' });
    y += 8;

    doc.setFontSize(12);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(148, 163, 184); // slate-400
    doc.text('AI Code Compliance Certificate', pageWidth / 2, y, { align: 'center' });
    y += 15;

    // Divider line
    doc.setDrawColor(51, 65, 85); // slate-700
    doc.setLineWidth(0.5);
    doc.line(margin + 20, y, pageWidth - margin - 20, y);
    y += 15;

    // TrustScore Circle
    const centerX = pageWidth / 2;
    const scoreColor: [number, number, number] = auditResult.TrustScore >= 80 ? [52, 211, 153] : // emerald-400
                       auditResult.TrustScore >= 60 ? [34, 211, 238] : // cyan-400
                       auditResult.TrustScore >= 40 ? [251, 191, 36] : // amber-400
                       [251, 113, 133]; // rose-400

    // Circle background
    doc.setFillColor(30, 41, 59); // slate-800
    doc.circle(centerX, y + 15, 22, 'F');
    
    // Circle border
    doc.setDrawColor(51, 65, 85);
    doc.setLineWidth(1.5);
    doc.circle(centerX, y + 15, 22, 'S');

    // Score text
    doc.setTextColor(...scoreColor);
    doc.setFontSize(28);
    doc.setFont('helvetica', 'bold');
    doc.text(String(auditResult.TrustScore), centerX, y + 12, { align: 'center' });
    
    doc.setFontSize(10);
    doc.setTextColor(148, 163, 184);
    doc.text('/ 100', centerX, y + 20, { align: 'center' });
    y += 42;

    // Score label
    const scoreLabel = auditResult.TrustScore >= 80 ? 'EXCELLENT' :
                       auditResult.TrustScore >= 60 ? 'GOOD' :
                       auditResult.TrustScore >= 40 ? 'MODERATE' : 'CRITICAL';
    doc.setTextColor(...scoreColor);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(scoreLabel, pageWidth / 2, y, { align: 'center' });
    y += 15;

    // Stats grid
    doc.setDrawColor(51, 65, 85);
    doc.setLineWidth(0.3);
    
    const stats = [
      { label: 'Total Issues', value: String(auditResult.AuditMetadata.total_findings) },
      { label: 'Critical/High', value: String(auditResult.Findings.filter(f =>
        f.severity === 'critical' || f.severity === 'high').length) },
      { label: 'Audit Date', value: new Date(auditResult.AuditMetadata.audit_date).toLocaleDateString() }
    ];

    const statWidth = (pageWidth - margin * 2 - 20) / 3;
    stats.forEach((stat, i) => {
      const x = margin + i * (statWidth + 10);
      doc.setFillColor(15, 23, 42); // slate-900
      doc.roundedRect(x, y, statWidth, 25, 3, 3, 'F');
      
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(18);
      doc.setFont('helvetica', 'bold');
      doc.text(stat.value, x + statWidth / 2, y + 11, { align: 'center' });
      
      doc.setFontSize(8);
      doc.setTextColor(148, 163, 184);
      doc.setFont('helvetica', 'normal');
      doc.text(stat.label, x + statWidth / 2, y + 19, { align: 'center' });
    });
    y += 40;

    // Findings section
    if (auditResult.Findings.length > 0) {
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(16);
      doc.setFont('helvetica', 'bold');
      doc.text('Detailed Findings', margin, y);
      y += 8;

      // Table
      const tableData = auditResult.Findings.map(f => [
        f.severity.toUpperCase(),
        f.category,
        f.message.substring(0, 50) + (f.message.length > 50 ? '...' : ''),
        String(f.line)
      ]);

      autoTable(doc, {
        startY: y,
        head: [['Severity', 'Category', 'Issue', 'Line']],
        body: tableData,
        theme: 'grid',
        styles: {
          fillColor: [15, 23, 42],
          textColor: [226, 232, 240],
          fontSize: 8,
          cellPadding: 4,
          lineColor: [51, 65, 85],
          lineWidth: 0.3
        },
        headStyles: {
          fillColor: [6, 182, 212],
          textColor: [255, 255, 255],
          fontStyle: 'bold'
        },
        columnStyles: {
          0: { cellWidth: 25 },
          1: { cellWidth: 35 },
          2: { cellWidth: 100 },
          3: { cellWidth: 20, halign: 'center' }
        },
        didParseCell: function(data: any) {
          if (data.section === 'body' && data.column.index === 0) {
            const severity = data.cell.raw.toLowerCase();
            if (severity.includes('critical')) {
              data.cell.styles.fillColor = [225, 29, 72]; // rose-600
            } else if (severity.includes('high')) {
              data.cell.styles.fillColor = [244, 63, 94]; // rose-500
            } else if (severity.includes('medium')) {
              data.cell.styles.fillColor = [245, 158, 11]; // amber-500
            } else if (severity.includes('low')) {
              data.cell.styles.fillColor = [6, 182, 212]; // cyan-500
            }
          }
        },
        margin: { left: margin, right: margin }
      });

      y = (doc as any).lastAutoTable.finalY + 15;
    }

    // Recommendation section
    if (y > pageHeight - 80) {
      doc.addPage();
      y = 20;
    }

    doc.setFillColor(15, 23, 42);
    doc.roundedRect(margin, y, pageWidth - margin * 2, 45, 4, 4, 'F');
    
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('PhD-Level Recommendation', margin + 8, y + 10);
    
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(203, 213, 225); // slate-300
    
    const recLines = doc.splitTextToSize(auditResult.PhD_Level_Recommendation, pageWidth - margin * 2 - 16);
    doc.text(recLines, margin + 8, y + 18);

    // Footer
    y = pageHeight - 35;
    doc.setDrawColor(30, 41, 59);
    doc.setLineWidth(0.5);
    doc.line(margin, y, pageWidth - margin, y);
    y += 10;

    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139); // slate-500
    doc.text('TrustCode AI Engine v1.0.0 | Certified by PhD Research Standards', pageWidth / 2, y, { align: 'center' });
    y += 5;
    doc.text('Created by Ali Hasan | https://alool266.github.io/portfolio-website/', pageWidth / 2, y, { align: 'center' });

    // Save
    doc.save(`TrustCode_Certificate_${new Date().toISOString().split('T')[0]}.pdf`);
  };

  return (
    <div className="min-h-screen bg-[#020617] text-slate-200">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h1 className="text-xl font-bold text-white">TrustCode AI</h1>
          </div>
          <div className="text-sm text-slate-400">
            PhD Research Standards
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-16">
        {/* Hero Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            AI Code Compliance
          </h2>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            Detect AI hallucinations, logic risks, and security vulnerabilities in your Python code. 
            Get a professional compliance certificate.
          </p>
        </motion.div>

        {/* Upload Section */}
        <AnimatePresence mode="wait">
          {!isScanning && !result && (
            <motion.div
              key="upload"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.3 }}
            >
              <div
                onDrop={onDrop}
                onDragOver={onDragOver}
                onDragLeave={onDragLeave}
                className="glass rounded-2xl p-16 text-center cursor-pointer transition-all hover:border-cyan-500/50 hover:bg-white/10"
              >
                <input
                  type="file"
                  accept=".py,.zip"
                  onChange={onFileSelect}
                  className="hidden"
                  id="file-upload"
                />
                <label htmlFor="file-upload" className="cursor-pointer">
                  <div className="w-20 h-20 mx-auto mb-6 rounded-full bg-slate-800/50 flex items-center justify-center">
                    <svg className="w-10 h-10 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                  </div>
                  <h3 className="text-2xl font-semibold text-white mb-2">
                    Drop your code file here
                  </h3>
                  <p className="text-slate-400 mb-4">
                    or click to browse
                  </p>
                  <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-sm">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Supports .py and .zip files up to 10MB
                  </div>
                </label>
              </div>
              
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mt-6 p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-center"
                >
                  {error}
                </motion.div>
              )}
            </motion.div>
          )}

          {/* Scanning Animation */}
          {isScanning && (
            <motion.div
              key="scanning"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="glass rounded-2xl p-16 text-center"
            >
              <div className="relative w-24 h-24 mx-auto mb-8">
                <div className="absolute inset-0 rounded-full border-4 border-slate-700/30"></div>
                <div className="absolute inset-0 rounded-full border-4 border-cyan-500 border-t-transparent animate-spin"></div>
                <div className="absolute inset-2 rounded-full border-2 border-cyan-400/30 border-b-transparent animate-spin-slow"></div>
              </div>
              
              <h3 className="text-2xl font-semibold text-white mb-2">
                Scanning your code...
              </h3>
              <p className="text-slate-400 mb-6">
                Analyzing for AI hallucinations and logic risks
              </p>
              
              <div className="w-full max-w-md mx-auto">
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <motion.div
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500"
                    initial={{ width: 0 }}
                    animate={{ width: `${scanProgress}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>
                <p className="text-sm text-slate-500 mt-2">
                  {scanProgress}% complete
                </p>
              </div>
              
              <div className="mt-8 flex flex-wrap justify-center gap-2">
                {['Parsing AST', 'Checking APIs', 'Detecting risks', 'Generating report'].map((step, i) => (
                  <div
                    key={step}
                    className={`px-3 py-1 rounded-full text-xs ${
                      scanProgress > i * 25
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : 'bg-slate-800/50 text-slate-500'
                    }`}
                  >
                    {step}
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {/* Results Section */}
          {result && (
            <motion.div
              key="results"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="space-y-6"
            >
              {/* Score Card */}
              <div className="glass rounded-2xl p-8 text-center">
                <div className="mb-6">
                  <div className="inline-flex items-center justify-center w-32 h-32 rounded-full bg-slate-800/50 border-4 border-slate-700/50 mb-4">
                    <div className="text-center">
                      <div className={`text-4xl font-bold ${getScoreColor(result.TrustScore)}`}>
                        {result.TrustScore}
                      </div>
                      <div className="text-xs text-slate-400">/ 100</div>
                    </div>
                  </div>
                  <div className={`text-lg font-semibold ${getScoreColor(result.TrustScore)}`}>
                    {getScoreLabel(result.TrustScore)}
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-bold text-white">{result.AuditMetadata.total_findings}</div>
                    <div className="text-sm text-slate-400">Issues Found</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-cyan-400">
                      {result.Findings.filter(f => f.severity === 'critical' || f.severity === 'high').length}
                    </div>
                    <div className="text-sm text-slate-400">Critical/High</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-white">
                      {new Date(result.AuditMetadata.audit_date).toLocaleDateString()}
                    </div>
                    <div className="text-sm text-slate-400">Audit Date</div>
                  </div>
                </div>
              </div>

              {/* Filter Controls */}
              {(result.FileResults || result.Findings.length > 0) && (
                <div className="glass rounded-2xl p-4">
                  <div className="flex flex-wrap gap-4 items-center">
                    {/* Search */}
                    <div className="flex-1 min-w-[200px]">
                      <input
                        type="text"
                        placeholder="Search findings..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full px-4 py-2 bg-slate-800/50 border border-slate-700/50 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 transition-colors"
                      />
                    </div>
                    
                    {/* Severity Filter */}
                    <div className="min-w-[150px]">
                      <select
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                        className="w-full px-4 py-2 bg-slate-800/50 border border-slate-700/50 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500/50 transition-colors"
                      >
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </select>
                    </div>

                    {/* Results Summary */}
                    <div className="text-sm text-slate-400">
                      {(() => {
                        const allFindings = result.FileResults
                          ? result.FileResults.flatMap(fr => fr.Findings)
                          : result.Findings;
                        const filtered = allFindings.filter(f => {
                          const matchesSearch = !searchQuery ||
                            f.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
                            f.category.toLowerCase().includes(searchQuery.toLowerCase());
                          const matchesSeverity = severityFilter === 'all' ||
                            f.severity.toLowerCase() === severityFilter;
                          return matchesSearch && matchesSeverity;
                        });
                        return <span>{filtered.length} of {allFindings.length} findings shown</span>;
                      })()}
                    </div>
                  </div>
                </div>
              )}

              {/* File Tree View (for project scans) */}
              {result.FileResults && result.FileResults.length > 0 && (
                <div className="glass rounded-2xl p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">
                    Project Files ({result.ScannedFiles} / {result.TotalFiles})
                  </h3>
                  <div className="space-y-2">
                    {result.FileResults.map((fileResult, idx) => (
                      <div key={idx} className="border border-slate-700/50 rounded-lg overflow-hidden">
                        <button
                          onClick={() => {
                            const newExpanded = new Set(expandedFiles);
                            if (newExpanded.has(fileResult.file)) {
                              newExpanded.delete(fileResult.file);
                            } else {
                              newExpanded.add(fileResult.file);
                            }
                            setExpandedFiles(newExpanded);
                          }}
                          className="w-full flex items-center justify-between p-4 bg-slate-800/30 hover:bg-slate-800/50 transition-colors"
                        >
                          <div className="flex items-center gap-3">
                            <svg
                              className={`w-5 h-5 text-cyan-400 transition-transform ${expandedFiles.has(fileResult.file) ? 'rotate-90' : ''}`}
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                            </svg>
                            <span className="text-slate-200 font-mono text-sm">{fileResult.file}</span>
                          </div>
                          <div className="flex items-center gap-4">
                            <div className="text-right">
                              <div className={`text-lg font-bold ${getScoreColor(fileResult.TrustScore)}`}>
                                {fileResult.TrustScore}
                              </div>
                              <div className="text-xs text-slate-400">{fileResult.Findings.length} issues</div>
                            </div>
                            {fileResult.error && (
                              <span className="px-2 py-1 rounded text-xs bg-rose-500/20 text-rose-400">
                                Error
                              </span>
                            )}
                          </div>
                        </button>
                        
                        {expandedFiles.has(fileResult.file) && (
                          <div className="border-t border-slate-700/50 p-4 bg-slate-900/30">
                            {fileResult.error ? (
                              <p className="text-rose-400 text-sm">{fileResult.error}</p>
                            ) : fileResult.Findings.length === 0 ? (
                              <p className="text-emerald-400 text-sm">No issues found</p>
                            ) : (
                              <div className="space-y-3">
                                {fileResult.Findings
                                  .filter(f => {
                                    const matchesSearch = !searchQuery ||
                                      f.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
                                      f.category.toLowerCase().includes(searchQuery.toLowerCase());
                                    const matchesSeverity = severityFilter === 'all' ||
                                      f.severity.toLowerCase() === severityFilter;
                                    return matchesSearch && matchesSeverity;
                                  })
                                  .map((finding, findingIdx) => (
                                    <div key={findingIdx} className="p-3 rounded bg-slate-800/50 border border-slate-700/30">
                                      <div className="flex items-start justify-between gap-3">
                                        <div className="flex-1">
                                          <div className="flex items-center gap-2 mb-1">
                                            <span className={`px-2 py-0.5 rounded text-xs font-semibold text-white ${getSeverityColor(finding.severity)}`}>
                                              {finding.severity.toUpperCase()}
                                            </span>
                                            <span className="text-xs text-slate-400">Line {finding.line}</span>
                                          </div>
                                          <p className="text-sm text-slate-200 mb-1">{finding.message}</p>
                                          <p className="text-xs text-slate-400 font-mono">{finding.snippet}</p>
                                        </div>
                                      </div>
                                    </div>
                                  ))
                                }
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Enhanced Visualizations */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Severity Distribution Pie Chart */}
                <div className="glass rounded-2xl p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">
                    Severity Distribution
                  </h3>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={[
                            { name: 'Critical', value: result.Findings.filter(f => f.severity === 'critical').length, color: '#e11d48' },
                            { name: 'High', value: result.Findings.filter(f => f.severity === 'high').length, color: '#f43f5e' },
                            { name: 'Medium', value: result.Findings.filter(f => f.severity === 'medium').length, color: '#f59e0b' },
                            { name: 'Low', value: result.Findings.filter(f => f.severity === 'low').length, color: '#06b6d4' },
                          ]}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                          outerRadius={80}
                          fill="#8884d8"
                          dataKey="value"
                        >
                          {[
                            { name: 'Critical', value: result.Findings.filter(f => f.severity === 'critical').length, color: '#e11d48' },
                            { name: 'High', value: result.Findings.filter(f => f.severity === 'high').length, color: '#f43f5e' },
                            { name: 'Medium', value: result.Findings.filter(f => f.severity === 'medium').length, color: '#f59e0b' },
                            { name: 'Low', value: result.Findings.filter(f => f.severity === 'low').length, color: '#06b6d4' },
                          ].map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1e293b',
                            border: '1px solid #475569',
                            borderRadius: '8px',
                            color: '#f1f5f9'
                          }}
                        />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Findings by Category Bar Chart */}
                <div className="glass rounded-2xl p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">
                    Issues by Category
                  </h3>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={Object.entries(
                        result.Findings.reduce((acc, f) => {
                          acc[f.category] = (acc[f.category] || 0) + 1;
                          return acc;
                        }, {} as Record<string, number>)
                      ).map(([name, value]) => ({ name, value }))}>
                        <XAxis
                          dataKey="name"
                          tick={{ fill: '#94a3b8', fontSize: 12 }}
                          axisLine={{ stroke: '#475569' }}
                          tickLine={{ stroke: '#475569' }}
                        />
                        <YAxis
                          tick={{ fill: '#94a3b8', fontSize: 12 }}
                          axisLine={{ stroke: '#475569' }}
                          tickLine={{ stroke: '#475569' }}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1e293b',
                            border: '1px solid #475569',
                            borderRadius: '8px',
                            color: '#f1f5f9'
                          }}
                        />
                        <Legend />
                        <Bar
                          dataKey="value"
                          fill="url(#barGradient)"
                          radius={[4, 4, 0, 0]}
                        >
                          <defs>
                            <linearGradient id="barGradient" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="0%" stopColor="#06b6d4" />
                              <stop offset="100%" stopColor="#3b82f6" />
                            </linearGradient>
                          </defs>
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>

              {/* CVSS Score Radial Chart */}
              <div className="glass rounded-2xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">
                  CVSS Severity Breakdown
                </h3>
                <div className="h-80">
                  <ResponsiveContainer width="100%" height="100%">
                    <RadialBarChart
                      cx="50%"
                      cy="50%"
                      innerRadius="10%"
                      outerRadius="80%"
                      barSize={20}
                      data={[
                        { name: 'Critical', value: result.Findings.filter(f => f.severity === 'critical').length, fill: '#e11d48' },
                        { name: 'High', value: result.Findings.filter(f => f.severity === 'high').length, fill: '#f43f5e' },
                        { name: 'Medium', value: result.Findings.filter(f => f.severity === 'medium').length, fill: '#f59e0b' },
                        { name: 'Low', value: result.Findings.filter(f => f.severity === 'low').length, fill: '#06b6d4' },
                      ]}
                    >
                      <RadialBar
                        dataKey="value"
                        background
                      />
                      <Legend
                        iconSize={10}
                        layout="vertical"
                        verticalAlign="middle"
                        align="right"
                        wrapperStyle={{ color: '#94a3b8' }}
                      />
                    </RadialBarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Findings Table */}
              {(() => {
                // Determine which findings to show based on project/single file
                const allFindings = result.FileResults
                  ? result.FileResults.flatMap(fr => fr.Findings.map(f => ({...f, file: fr.file})))
                  : result.Findings.map(f => ({...f, file: result.AuditMetadata.file}));

                const filteredFindings = allFindings.filter(f => {
                  const matchesSearch = !searchQuery ||
                    f.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
                    f.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
                    f.file.toLowerCase().includes(searchQuery.toLowerCase());
                  const matchesSeverity = severityFilter === 'all' ||
                    f.severity.toLowerCase() === severityFilter;
                  return matchesSearch && matchesSeverity;
                });

                if (filteredFindings.length === 0) {
                  return null;
                }

                return (
                  <div className="glass rounded-2xl p-6 overflow-hidden">
                    <h3 className="text-xl font-semibold text-white mb-4">
                      Detailed Findings ({filteredFindings.length} of {allFindings.length})
                    </h3>
                    <div className="overflow-x-auto">
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-slate-700/50">
                            <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">Severity</th>
                            <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">Category</th>
                            <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">File</th>
                            <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">Issue</th>
                            <th className="text-center py-3 px-4 text-sm font-semibold text-slate-300">Line</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredFindings.map((finding, idx) => (
                            <motion.tr
                              key={idx}
                              initial={{ opacity: 0, x: -10 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ delay: idx * 0.05 }}
                              className="border-b border-slate-800/30 hover:bg-slate-800/20"
                            >
                              <td className="py-3 px-4">
                                <span className={`inline-block px-2 py-1 rounded text-xs font-semibold text-white ${getSeverityColor(finding.severity)}`}>
                                  {finding.severity.toUpperCase()}
                                </span>
                              </td>
                              <td className="py-3 px-4 text-sm text-slate-300">{finding.category}</td>
                              <td className="py-3 px-4 text-sm text-slate-400 font-mono max-w-[200px] truncate" title={finding.file}>
                                {finding.file}
                              </td>
                              <td className="py-3 px-4 text-sm text-slate-200">{finding.message}</td>
                              <td className="py-3 px-4 text-center text-sm text-slate-400 font-mono">{finding.line}</td>
                            </motion.tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                );
              })()}

              {/* Recommendation */}
              <div className="glass rounded-2xl p-6">
                <h3 className="text-xl font-semibold text-white mb-4">
                  PhD-Level Recommendation
                </h3>
                <p className="text-slate-300 leading-relaxed italic">
                  {result.PhD_Level_Recommendation}
                </p>
              </div>

              {/* Download Button */}
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 }}
                className="flex justify-center"
              >
                <button
                  onClick={() => generateCertificate(result)}
                  className="group flex items-center gap-3 px-8 py-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 rounded-full text-white font-semibold shadow-lg shadow-cyan-500/25 transition-all hover:scale-105 active:scale-95"
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Download Certificate
                </button>
              </motion.div>

              {/* Reset */}
              <div className="text-center mt-6">
                <button
                  onClick={() => {
                    setResult(null);
                    setError(null);
                  }}
                  className="text-slate-400 hover:text-white transition-colors text-sm"
                >
                  Audit another file
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 mt-20 py-8">
        <div className="max-w-6xl mx-auto px-6 text-center text-slate-500 text-sm">
          <p>TrustCode AI Engine v1.0.0 | Certified by PhD Research Standards</p>
          <p className="mt-1">Static analysis for AI hallucinations and logic risks</p>
        </div>
      </footer>
    </div>
  );
}
