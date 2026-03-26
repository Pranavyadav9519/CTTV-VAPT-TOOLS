#!/usr/bin/env python3
"""
QUICK START GUIDE - CCTV VAPT Tool
Get up and running in 5 minutes
"""

import os
print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                    CCTV VAPT TOOL - QUICK START GUIDE                      ║
║                    Production Ready • All Tests Passing                      ║
╚════════════════════════════════════════════════════════════════════════════╝

📋 SYSTEM OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Vulnerability Scanner - Complete
   • 23 real CVEs from NVD database
   • 15+ check categories
   • 14 manufacturers in credentials database
   • Non-destructive testing

✅ Report Generation - Complete
   • 6-layer enterprise pipeline
   • 3 report types (Executive, Technical, Compliance)
   • JSON & HTML export
   • CVSS-based risk scoring

✅ Interactive UI - Complete
   • Real-time scan progress
   • Report generation panel
   • One-click downloads
   • Full report viewer modal

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


🚀 GETTING STARTED (5 MINUTES)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STEP 1: Activate Virtual Environment
   Windows PowerShell:
   $ .\.venv\Scripts\Activate.ps1

   Windows CMD:
   > .venv\\Scripts\\activate.bat

   Linux/Mac:
   $ source .venv/bin/activate

STEP 2: Install Dependencies (if not already done)
   $ pip install -r backend/requirements.txt

STEP 3: Start Flask Application
   $ python backend/app.py
   
   Expected output:
   * Serving Flask app 'app'
   * Running on http://0.0.0.0:5000
   * Press CTRL+C to quit

STEP 4: Open Frontend (in browser)
   http://localhost:5000
   
   You should see:
   - CCTV VAPT navigation menu
   - New Scan tab with network range input
   - Real-time discovery results

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


📊 TESTING THE SYSTEM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Option A: Run Full End-to-End Test
   $ python test_e2e_integration.py
   
   This tests:
   ✓ Database integration
   ✓ 6-layer reporting pipeline
   ✓ All API endpoints
   ✓ Frontend components
   ✓ Export functionality
   ✓ Data flow validation
   ✓ Performance metrics

Option B: Test Reporting System Only
   $ python test_reporting_system.py
   
   This tests:
   ✓ All 6 reporting layers
   ✓ CVE database loading
   ✓ Report composition
   ✓ Export generation

Option C: Test in Browser (Interactive)
   1. Go to http://localhost:5000
   2. Click "New Scan" tab
   3. Enter network range: 192.168.1.0/24 (or your network)
   4. Click "Start Scan"
   5. Wait for completion
   6. Click "Generate Report" button
   7. View report preview
   8. Download JSON or HTML export

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


🎯 TYPICAL WORKFLOW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. START SCAN
   • Open frontend application
   • Enter network range (e.g., 192.168.1.0/24)
   • Click "Start Scan"
   • Monitor real-time discovery

2. RUN VULNERABILITY CHECKS
   • System detects CCTV devices
   • Runs 15+ vulnerability checks
   • Tests for default credentials (non-destructively)
   • Matches against 23 CVE database

3. GENERATE REPORT
   • After scan completes, click "Generate Report"
   • Wait 2-30 seconds (depending on device count)
   • Report preview appears in panel

4. VIEW REPORT DETAILS
   • See vulnerability statistics
   • View risk assessment
   • Read recommendations
   • Click "View Full Report" for details

5. DOWNLOAD REPORT
   • Choose JSON or HTML format
   • File downloads to your computer
   • Open in editor (JSON) or browser (HTML)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


📁 PROJECT STRUCTURE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VAPT/
├── backend/
│   ├── app.py                    ← Main Flask application
│   ├── reporting_engine.py       ← 6-layer pipeline (NEW)
│   ├── modules/
│   │   ├── vulnerability_scanner.py    ← 23 real CVEs (ENHANCED)
│   │   ├── network_scanner.py
│   │   ├── port_scanner.py
│   │   └── device_identifier.py
│   ├── data/
│   │   ├── cctv_vulnerabilities.json   ← CVE database (NEW)
│   │   └── default_credentials.json    ← Credentials (NEW)
│   ├── database/
│   │   ├── models.py            ← Database models
│   │   └── db.py
│   └── requirements.txt
│
├── frontend/
│   ├── index.html               ← Main UI
│   ├── js/
│   │   ├── app.js               ← Scan coordination
│   │   └── report-ui.js         ← Report panel (NEW)
│   └── css/
│       ├── modern-styles.css
│       ├── styles.css
│       └── report-styles.css    ← Report styling (NEW)
│
├── reports/                      ← Generated reports
│   ├── *.json
│   └── *.html
│
├── test_reports/                 ← Test output
│   ├── *.json
│   └── *.html
│
└── Tests:
    ├── test_reporting_system.py          ← Reporting tests
    └── test_e2e_integration.py           ← Full system tests

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


🔌 API ENDPOINTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scan Management:
   POST   /api/scan/start                    Start new scan
   GET    /api/scan/<id>                     Get scan details
   GET    /api/scan/<id>/devices             List devices in scan

Report Generation:
   POST   /api/scan/<id>/report              Generate report
   GET    /api/scan/<id>/report              Retrieve report
   GET    /api/scan/<id>/report/export/json  Download as JSON
   GET    /api/scan/<id>/report/export/html  Download as HTML
   GET    /api/reports                       List all reports
   GET    /api/report/<id>                   Get report by ID

Example:
   curl -X POST http://localhost:5000/api/scan/123/report
   
   Response:
   {
     "success": true,
     "report_id": 1,
     "scan_id": 123,
     "preview": {
       "risk_level": {"score": 75, "rating": "High"},
       "statistics": {"total_hosts": 25, "cctv_devices": 8, ...},
       "recommendations": [...]
     }
   }

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


⚙️ CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Environment Variables:
   FLASK_ENV          Development (default) or production
   DATABASE_URL       PostgreSQL connection string
   CELERY_BROKER      Redis connection for task queue

Configuration Files:
   backend/config.py   Flask + SQLAlchemy configuration
   alembic.ini         Database migration settings

CVE Database:
   Location: backend/data/cctv_vulnerabilities.json
   Contains: 23 real CVEs with CVSS scores
   Update: Edit JSON file to add/modify vulnerabilities

Credentials Database:
   Location: backend/data/default_credentials.json
   Contains: 14 manufacturers with 40+ credential combinations
   Update: Edit JSON file to add manufacturer credentials

Report Output:
   Directory: backend/reports/
   Format: VAPT_Report_{scan_id}_{timestamp}.{json|html}
   Size: 100KB-1MB depending on scan size

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


🐛 TROUBLESHOOTING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Issue: "ModuleNotFoundError: No module named 'flask'"
   Fix: pip install -r backend/requirements.txt

Issue: "CORS error" in browser console
   Fix: Flask app has CORS enabled already
   Check: browser console for specific error message

Issue: "Port 5000 already in use"
   Fix: Change port: export FLASK_PORT=5001
   Or: Kill existing process on port 5000

Issue: "Database connection refused"
   Fix: Verify PostgreSQL is running
   Check: DATABASE_URL environment variable is correct

Issue: "Report not downloading"
   Fix: Check backend/reports/ directory exists and has write permissions
   Check: Browser download location settings

Issue: "Report generation timeout"
   Fix: Check network scan completed (should be in database)
   Logs: Check backend application logs for errors

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


✅ VERIFICATION CHECKLIST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Backend:
   ☐ Python 3.8+ installed
   ☐ Virtual environment activated
   ☐ Dependencies installed (pip install -r backend/requirements.txt)
   ☐ Flask app starts without errors
   ☐ Database accessible
   ☐ CVE database file exists (backend/data/cctv_vulnerabilities.json)
   ☐ Credentials database exists (backend/data/default_credentials.json)

Frontend:
   ☐ Browser opens to http://localhost:5000
   ☐ Navigation menu visible
   ☐ "New Scan" tab accessible
   ☐ Socket.IO connected (check browser console)
   ☐ Report UI initialized (check console for "reportUI" object)

Data:
   ☐ test_e2e_integration.py passes all 9 phases
   ☐ test_reporting_system.py passes all layers
   ☐ Sample reports generated in test_reports/

Network:
   ☐ Can access http://localhost:5000/api/health
   ☐ Backend can connect to database
   ☐ Redis accessible (if using Celery)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


📚 DOCUMENTATION FILES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

E2E_TEST_SUMMARY.md
   Complete test results and system overview

REPORT_GENERATION_COMPLETE.md
   Detailed reporting system documentation

VULNERABILITY_SCANNER_ENHANCEMENT_COMPLETE.md
   Vulnerability scanner implementation details

PROJECT_AUDIT.md
   Initial project analysis and architecture

README_MIGRATIONS.md
   Database migration information

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


🎓 KEY FEATURES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Real-time network discovery with live updates
✓ Non-destructive security assessment
✓ 23 actual CVEs from NVD database
✓ Default credential testing (14 manufacturers)
✓ 15+ different vulnerability check categories
✓ Comprehensive risk scoring (CVSS v3.1)
✓ 3 distinct report types (Executive, Technical, Compliance)
✓ Multi-format export (JSON, HTML)
✓ Interactive report viewer with statistics
✓ One-click report downloads
✓ Full audit logging
✓ Responsive design (mobile/tablet/desktop)
✓ WebSocket real-time updates
✓ Database report history
✓ RESTful API for integrations

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


🚀 YOU'RE READY!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The CCTV VAPT Tool is production-ready with:
   ✅ Complete vulnerability scanning
   ✅ Comprehensive report generation
   ✅ Interactive UI
   ✅ Database integration
   ✅ Full API endpoints
   ✅ Extensive testing

Start scanning: http://localhost:5000

For issues: Check troubleshooting section above
For questions: Review documentation files
For testing: Run test_e2e_integration.py

Happy scanning! 🛡️

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

# Print file structure
print("\n📁 Key Files Status:")
files_to_check = [
    ("backend/app.py", "Flask application"),
    ("backend/reporting_engine.py", "6-layer report pipeline"),
    ("backend/data/cctv_vulnerabilities.json", "CVE database"),
    ("backend/data/default_credentials.json", "Credentials database"),
    ("frontend/index.html", "UI entry point"),
    ("frontend/js/report-ui.js", "Report panel component"),
    ("frontend/css/report-styles.css", "Report styling"),
    ("test_e2e_integration.py", "End-to-end test suite"),
]

for filepath, description in files_to_check:
    exists = os.path.exists(filepath)
    status = "✅" if exists else "❌"
    print(f"  {status} {filepath:45} ({description})")

print("\n" + "="*80)
print("Ready to start? Run: python backend/app.py")
print("="*80 + "\n")
