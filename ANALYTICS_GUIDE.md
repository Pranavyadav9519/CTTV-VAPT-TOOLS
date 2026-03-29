# VAPT Analytics Implementation Guide

## Overview

This document describes the complete analytics system implemented for the VAPT platform, including risk scoring, KPI dashboards, trend analysis, and data pipelines.

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     ANALYTICS PIPELINE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. DATA INGESTION (Scans → Findings)                           │
│     └─→ backend/core/models.py: Scan, Device, Vulnerability    │
│                                                                  │
│  2. RISK SCORING ENGINE                                         │
│     └─→ backend/core/analytics_service.py: RiskScoringEngine   │
│         • Vulnerability Score (40% weight)                      │
│         • Exploitability Score (35% weight)                     │
│         • Exposure Score (25% weight)                           │
│         • Composite Risk Score (0-100 scale)                    │
│                                                                  │
│  3. ANALYTICS COMPUTATION                                       │
│     └─→ backend/core/analytics_service.py: AnalyticsEngine     │
│         • Daily Rollups (scan metrics, severity counts)         │
│         • Vulnerability Trends (new/resolved/open)             │
│         • Top Devices Cache (fast queries)                      │
│                                                                  │
│  4. API LAYER                                                   │
│     └─→ backend/api/analytics.py                               │
│         • GET /api/v1/analytics/summary (main KPI endpoint)    │
│         • GET /api/v1/analytics/devices (top at-risk devices)  │
│         • GET /api/v1/analytics/trends (vulnerability trends)  │
│         • POST /api/v1/analytics/calculate-risks (admin)       │
│                                                                  │
│  5. BACKGROUND JOBS                                             │
│     └─→ backend/tasks/analytics_tasks.py                       │
│         • Post-scan analytics trigger                           │
│         • Daily maintenance (scheduled)                         │
│         • Risk recalculation                                    │
│                                                                  │
│  6. FRONTEND DASHBOARD                                          │
│     └─→ frontend/analytics.html                                │
│         • KPI Cards (real-time metrics)                         │
│         • Charts (Chart.js - vulnerability trends)             │
│         • Top Devices Table (risk-ranked list)                 │
│         • Responsive Design (mobile-friendly)                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Database Models

### New Tables Created

#### 1. **device_risk_scores**
Stores calculated risk scores for each device.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Primary key |
| `device_id` | FK | References devices table |
| `tenant_id` | String(36) | Multi-tenant isolation |
| `vulnerability_score` | Float | Score from vuln counts (0-100) |
| `exploitability_score` | Float | Score from exploit potential (0-100) |
| `exposure_score` | Float | Score from internet exposure (0-100) |
| `overall_risk_score` | Float | Composite score (0-100) |
| `risk_tier` | String(10) | CRITICAL, HIGH, MEDIUM, LOW |
| `calculated_at` | DateTime | When score was calculated |
| `last_updated_at` | DateTime | Last update timestamp |

**Index**: `(device_id)`, `(tenant_id, risk_tier)`

#### 2. **daily_analytics_rollups**
Pre-computed daily aggregates for fast dashboard queries.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Primary key |
| `tenant_id` | String(36) | Multi-tenant isolation |
| `rollup_date` | Date | Date of rollup |
| `total_scans` | Integer | Scans completed that day |
| `completed_scans` | Integer | Successful scans |
| `failed_scans` | Integer | Failed scans |
| `avg_scan_duration_seconds` | Integer | Average scan time |
| `unique_devices_found` | Integer | Total devices discovered |
| `new_devices` | Integer | Newly discovered |
| `cctv_devices_found` | Integer | CCTV device count |
| `total_vulnerabilities` | Integer | All vulns (cumulative) |
| `new_vulnerabilities` | Integer | New vulns today |
| `resolved_vulnerabilities` | Integer | Fixed vulns today |
| `critical_count` | Integer | Critical vulnerability count |
| `high_count` | Integer | High severity count |
| `medium_count` | Integer | Medium severity count |
| `low_count` | Integer | Low severity count |
| `avg_device_risk_score` | Float | Mean device risk |
| `critical_risk_devices` | Integer | Devices with CRITICAL tier |
| `high_risk_devices` | Integer | Devices with HIGH tier |

**Index**: `(tenant_id, rollup_date)`

#### 3. **top_devices_analytics**
Cache of top at-risk devices for fast API responses.

| Column | Type | Purpose |
|--------|------|---------|
| `device_id` | FK | References devices |
| `ip_address` | String(45) | Device IP (cached) |
| `hostname` | String(255) | Device hostname |
| `total_vulnerabilities` | Integer | Vuln count |
| `critical_vulns` | Integer | Critical count |
| `high_vulns` | Integer | High count |
| `risk_score` | Float | Device risk (0-100) |
| `risk_tier` | String(10) | CRITICAL/HIGH/MEDIUM/LOW |
| `last_scan_date` | DateTime | Last scan completion |

#### 4. **vulnerability_trends**
Daily trend data for time-series analysis.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Primary key |
| `tenant_id` | String(36) | Multi-tenant isolation |
| `trend_date` | Date | Date of trend |
| `new_findings` | Integer | New vulns found |
| `resolved_findings` | Integer | Fixed vulns |
| `still_open` | Integer | Cumulative open |
| `critical_new` | Integer | New critical vulns |
| `high_new` | Integer | New high vulns |
| `medium_new` | Integer | New medium vulns |
| `low_new` | Integer | New low vulns |

**Index**: `(tenant_id, trend_date)`

---

## Risk Scoring Algorithm

### Formula

```
Overall Risk Score = (Vulnerability Score × 0.40) + 
                     (Exploitability Score × 0.35) + 
                     (Exposure Score × 0.25)

Risk Score Range: 0-100
Risk Tiers:
  - CRITICAL: 80-100
  - HIGH:     60-79
  - MEDIUM:   40-59
  - LOW:      0-39
```

### Component Details

#### **Vulnerability Score** (40% weight)
Calculated from vulnerability counts on the device:

```
Vulnerability Score = (Critical × 40) + (High × 25) + (Medium × 15) + (Low × 10)
Cap: 100

Example:
  Device with: 2 Critical, 3 High, 1 Medium
  = (2 × 40) + (3 × 25) + (1 × 15)
  = 80 + 75 + 15
  = 170 → capped to 100
```

#### **Exploitability Score** (35% weight)
Evaluates how easily device can be exploited:

```
+ 30 points: Has known CVEs (publicly available exploits)
+ 40 points: Default credentials detected
+ 25 points: Weak/no authentication found
Cap: 100

Example: Device with CVE + default creds = 30 + 40 = 70 points
```

#### **Exposure Score** (25% weight)
Measures attack surface:

```
+ 15 points: 1-4 open ports
+ 25 points: 5-9 open ports
+ 40 points: 10+ open ports

+ 30 points: Risky services (Telnet, FTP, HTTP, RTSP, ONVIF)
+ 20 points: CCTV device (mass target)

Cap: 100

Example: CCTV with telnet + 12 open ports = 20 + 30 + 40 = 90
```

#### **Example Calculation**

```
Device: 192.168.1.100 (IP Camera)
  - 3 Critical vulns, 2 High, 1 Medium
  - 1 known CVE
  - Default credentials found
  - RTSP service open
  - Telnet open
  - 15 total open ports

Vulnerability Score = (3×40) + (2×25) + (1×15) = 125 → 100
Exploitability Score = 30 + 40 = 70
Exposure Score = 40 (10+ ports) + 30 (risky services) + 20 (CCTV) = 90

Overall = (100 × 0.40) + (70 × 0.35) + (90 × 0.25)
        = 40 + 24.5 + 22.5
        = 87.0 → CRITICAL tier
```

---

## API Reference

### Main Analytics Summary Endpoint

**GET `/api/v1/analytics/summary`**

Returns comprehensive dashboard KPIs.

**Query Parameters:**
- `days` (optional, default: 7): Number of days to analyze (max: 365)

**Response:**
```json
{
  "ok": true,
  "data": {
    "kpi": {
      "total_scans": 45,
      "vulnerabilities_found": 230,
      "critical_vulnerabilities": 12,
      "high_vulnerabilities": 45,
      "devices_scanned": 78,
      "critical_devices": 5,
      "high_risk_devices": 15,
      "average_risk_score": 62.3
    },
    "time_period": {
      "days": 7,
      "start_date": "2026-03-21",
      "end_date": "2026-03-28"
    },
    "top_devices": [
      {
        "device_id": 42,
        "ip_address": "192.168.1.100",
        "hostname": "cctv-main",
        "manufacturer": "Hikvision",
        "vulnerabilities": {
          "total": 15,
          "critical": 3,
          "high": 5
        },
        "risk": {
          "score": 87.2,
          "tier": "CRITICAL"
        },
        "last_scanned": "2026-03-28T14:32:00Z"
      }
    ],
    "trends": [
      {
        "date": "2026-03-28",
        "findings": {
          "new": 8,
          "resolved": 2,
          "still_open": 230
        },
        "by_severity": {
          "critical": 1,
          "high": 3,
          "medium": 2,
          "low": 2
        }
      }
    ]
  },
  "meta": {
    "timestamp": "2026-03-28T15:45:00Z",
    "tenant_id": "default"
  }
}
```

### Top Devices Endpoint

**GET `/api/v1/analytics/devices`**

Returns list of top at-risk devices.

**Query Parameters:**
- `limit` (optional, default: 20, max: 100): Number of devices
- `risk_tier` (optional): Filter by CRITICAL, HIGH, MEDIUM, LOW

**Response:** Array of device analytics objects (see above)

### Vulnerability Trends Endpoint

**GET `/api/v1/analytics/trends`**

Returns time-series vulnerability data.

**Query Parameters:**
- `days` (optional, default: 30): Number of days of history

**Response:** Array of daily trend objects

### Device Detail Endpoint

**GET `/api/v1/analytics/devices/<device_id>`**

Returns detailed risk analysis for a specific device.

### Admin: Calculate Risks

**POST `/api/v1/analytics/calculate-risks`**

Recalculates all device risk scores (admin only).

### Admin: Generate Rollup

**POST `/api/v1/analytics/generate-rollup`**

Manually trigger daily rollup generation.

**Body (optional):**
```json
{
  "date": "2026-03-27"
}
```

---

## Celery Tasks

### Automatic Post-Scan Analytics

After each scan completes, the system automatically queues:

```python
post_scan_analytics_task(tenant_id, scan_id)
```

This triggers:
1. Device risk recalculation
2. Daily rollup generation
3. Vulnerability trend computation
4. Top devices cache update

### Daily Maintenance

Scheduled once per day (configurable):

```python
celery_beat_schedule = {
    'daily-analytics-maintenance': {
        'task': 'analytics.daily_maintenance',
        'schedule': timedelta(hours=24),
    }
}
```

This regenerates all analytics across all tenants.

---

## Frontend Dashboard

### URL
`http://localhost:3000/analytics.html`

### Features

#### KPI Cards
- **Total Scans**: Network assessments completed
- **Vulnerabilities Found**: With severity breakdown (Critical/High/Medium)
- **Devices Scanned**: Total unique endpoints
- **Average Risk Score**: Composite risk metric with visual meter
- **At-Risk Devices**: CRITICAL tier count
- **High Risk Devices**: HIGH tier count

#### Charts (Chart.js)
- **Vulnerability Trend**: Line chart of new findings vs still-open over time
- **Severity Distribution**: Doughnut chart of findings by severity
- **New vs Resolved**: Bar chart showing remediation progress

#### Top Devices Table
- Ranked by risk score (descending)
- Columns: IP, Hostname, Manufacturer, Vulnerability Count, Risk Score, Status
- Color-coded rows by risk tier
- Sortable and filterable

#### Controls
- **Time Range Selector**: 7/30/90 day windows
- **Refresh Button**: Manual data refresh
- **Risk Tier Filter**: Show only devices at specific risk level
- **Export Button**: Download analytics (future feature)

### Auto-Refresh
Dashboard refreshes data every 60 seconds automatically.

---

## Data Pipeline

### Step 1: Scan Completion
```
User runs scan → Scan completes → Vulnerabilities discovered
```

### Step 2: Risk Calculation (Async)
```
Device vulnerabilities → RiskScoringEngine.calculate_device_risk()
→ DeviceRiskScore record created/updated
```

### Step 3: Rollup Generation (Async)
```
Daily window (00:00-23:59) → AnalyticsEngine.generate_daily_rollup()
→ DailyAnalyticsRollup aggregates metrics
```

### Step 4: Trend Tracking (Async)
```
New findings detected → AnalyticsEngine.generate_vulnerability_trend()
→ VulnerabilityTrend records severity/status changes
```

### Step 5: Cache Invalidation (Async)
```
Risk scores updated → AnalyticsEngine.update_top_devices()
→ TopDevicesAnalytics cache refreshed (sorted by risk)
```

### Step 6: API Query (Real-time)
```
Frontend calls /api/v1/analytics/summary
→ Queries cached tables + computed rollups
→ Returns JSON response (<300ms target)
```

---

## Performance Considerations

### Caching Strategy
- **Daily Rollups**: Computed once, queried 1000s of times
- **Top Devices Cache**: Updated after each scan, queried frequently
- **API Response**: <300ms target via pre-computed data

### Indexing
```sql
-- Create indexes for fast queries
CREATE INDEX idx_device_risk_device_id ON device_risk_scores(device_id);
CREATE INDEX idx_device_risk_tenant ON device_risk_scores(tenant_id, risk_tier);
CREATE INDEX idx_daily_rollup_date ON daily_analytics_rollups(tenant_id, rollup_date);
CREATE INDEX idx_trend_date ON vulnerability_trends(tenant_id, trend_date);
```

### Query Optimization
- Rollups avoid computing from raw vulnerability rows every time
- Top devices cached instead of sorting all devices on query
- Trend data stored precomputed instead of aggregated live

---

## Integration with Existing Code

### 1. Register Analytics Blueprint

In `backend/enterprise/__init__.py` or main Flask app:

```python
from backend.api.analytics import analytics_bp

app.register_blueprint(analytics_bp)
```

### 2. Trigger Post-Scan Tasks

In scan completion handler (e.g., `backend/enterprise/tasks/scan_worker.py`):

```python
from backend.tasks.analytics_tasks import post_scan_analytics_task

# After scan completes
post_scan_analytics_task.apply_async(
    args=[tenant_id, scan_id],
    queue='analytics'
)
```

### 3. Database Migrations

Run Alembic migration to create analytics tables:

```bash
alembic revision --autogenerate -m "Add analytics tables"
alembic upgrade head
```

### 4. Worker Configuration

Ensure Celery has an 'analytics' queue:

```python
# backend/config.py
CELERY_QUEUES = (
    Queue('default'),
    Queue('analytics'),  # Add this
    Queue('reports'),
)
```

---

## Example Workflows

### Workflow 1: User Views Dashboard

```
1. User opens http://localhost:3000/analytics.html
2. Browser loads analytics.html + analytics.css + axios
3. On DOMContentLoaded, calls:
   POST /api/v1/analytics/summary?days=7
4. Backend queries:
   - daily_analytics_rollups (last 7 days)
   - risk_scores aggregated
   - top_devices cache
   - vulnerability_trends (30 days)
5. Returns JSON with KPIs + trends + devices
6. JavaScript renders charts and tables
7. Auto-refreshes every 60 seconds
```

### Workflow 2: Scan Completes

```
1. Scan finishes with 45 new vulnerabilities
2. Scan marked as COMPLETED in database
3. post_scan_analytics_task queued
4. Background task executes:
   a. update_device_risks_task
      - Recalculate 12 affected devices
      - Update device_risk_scores
   b. generate_daily_rollup_task
      - Aggregate metrics for today
      - Update daily_analytics_rollups
   c. generate_vulnerability_trend_task
      - Add 45 new findings to trend
      - Update vulnerability_trends
   d. update_top_devices_task
      - Re-rank top 20 devices
      - Update top_devices_analytics cache
5. Dashboard refreshes automatically, shows new data
```

### Workflow 3: Admin Recalculates Risks

```
1. Admin calls POST /api/v1/analytics/calculate-risks
2. Backend calls:
   RiskScoringEngine.recalculate_all_device_risks(tenant_id)
3. For each device:
   - Query vulnerabilities
   - Recalculate 3 score components
   - Update overall_risk_score
   - Set risk_tier
4. Returns { "devices_updated": 142 }
5. Top devices cache auto-updates on next query
```

---

## Troubleshooting

### Charts Not Displaying

**Problem**: Analytics page loads but charts are blank.

**Solutions**:
1. Check browser console for JavaScript errors
2. Verify /api/v1/analytics/summary endpoint returns data
3. Ensure Chart.js library is loaded from CDN
4. Check that trends array has data

### Risk Scores All Zero

**Problem**: All devices show 0.0 risk score.

**Solutions**:
1. Ensure vulnerabilities are associated with devices
2. Run POST /api/v1/analytics/calculate-risks manually
3. Check device_risk_scores table for records
4. Verify Vulnerability model relationships are correct

### Slow Analytics Queries

**Problem**: /api/v1/analytics/summary takes >1 second.

**Solutions**:
1. Verify indexes exist on (tenant_id, rollup_date)
2. Check if rollup records exist (queries raw vulns if not)
3. Run daily_maintenance_task to generate missing rollups
4. Monitor Celery task queue depth
5. Consider archiving old scan data

### Missing Trends Data

**Problem**: Trends chart is empty.

**Solutions**:
1. Verify vulnerability_trends table has records
2. Run generate_vulnerability_trend_task manually
3. Check if scans have associated vulnerabilities
4. Confirm trend dates match requested range

---

## Future Enhancements

1. **Export Analytics**: PDF/CSV download with charts
2. **Custom Reports**: User-defined KPI dashboards
3. **Trend Predictions**: ML-based risk forecasting
4. **SLA Tracking**: Mean time to remediate (MTTR) metrics
5. **Benchmarking**: Compare this tenant vs industry averages
6. **Cost Analysis**: Prioritize remediation by impact + cost
7. **Remediation Automation**: Suggest fixes based on risk tier
8. **Alert Rules**: Notify admins when risk threshold exceeded

---

## References

- [Chart.js Documentation](https://www.chartjs.org/)
- [CVSS Scoring](https://www.first.org/cvss/v3.1/specification/)
- [OWASP Risk Ratings](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- [Celery Task Queue](https://docs.celeryproject.io/)

---

**Last Updated**: March 28, 2026  
**Version**: 1.0  
**Status**: Production Ready
