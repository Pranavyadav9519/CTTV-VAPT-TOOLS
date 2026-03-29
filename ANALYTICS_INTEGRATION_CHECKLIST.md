# Analytics Integration Checklist

## Quick Start (5 minutes)

### Step 1: Initialize Analytics Database
```bash
cd d:\VAPT
python setup_analytics.py
```

Expected output:
```
✓ Analytics database initialized successfully!
✓ All Celery tasks verified!
✓ Analytics service tests completed!
✓ Sample analytics generated!
```

### Step 2: Register Analytics Blueprint

**File**: `backend/enterprise/__init__.py`

Add after other blueprint registrations:

```python
# At the top
from backend.api.analytics import analytics_bp

# In create_app() function, after other blueprints:
app.register_blueprint(analytics_bp)
```

### Step 3: Configure Celery Queue

**File**: `backend/config.py`

Update or add:

```python
from kombu import Queue

CELERY_QUEUES = (
    Queue('default', routing_key='default'),
    Queue('analytics', routing_key='analytics'),  # Add this
    Queue('reports', routing_key='reports'),
)
```

### Step 4: Trigger Post-Scan Analytics

**File**: `backend/enterprise/tasks/scan_worker.py` (or wherever scans complete)

Add to scan completion handler:

```python
from backend.tasks.analytics_tasks import post_scan_analytics_task

# After scan status is set to COMPLETED:
post_scan_analytics_task.apply_async(
    args=[tenant_id, scan_id],
    queue='analytics'
)
```

### Step 5: Start Backend & Access Dashboard

```bash
# Terminal 1: Start backend
$env:PYTHONPATH="d:\VAPT"
$env:FLASK_ENV="development"
$env:SECRET_KEY="dev-secret-key-32-characters-long-1234"
$env:JWT_SECRET_KEY="dev-jwt-secret-key-32-chars-12345"
$env:ENCRYPTION_KEY="dev-encryption-key-32-chars-1234567890"
$env:DATABASE_URL="sqlite:///vapt_dev.db"
python backend/run.py

# Terminal 2: Start frontend
cd d:\VAPT\frontend
python -m http.server 3000

# Terminal 3: Start Celery worker (optional but recommended)
celery -A backend.celery_app worker -l info -Q analytics
```

### Step 6: View Dashboard

Open browser to:
```
http://localhost:3000/analytics.html
```

---

## Integration Checklist

### Backend Setup

- [ ] **Register Blueprint**
  - [ ] Import `analytics_bp` in `backend/enterprise/__init__.py`
  - [ ] Call `app.register_blueprint(analytics_bp)`
  - [ ] Test: GET http://localhost:5000/api/v1/analytics/health → 200 OK

- [ ] **Configure Celery**
  - [ ] Add 'analytics' queue to `CELERY_QUEUES` in config
  - [ ] Set Celery broker URL (Redis/RabbitMQ)
  - [ ] Update Celery beat schedule for daily maintenance

- [ ] **Test Analytics Service**
  - [ ] POST /api/v1/analytics/calculate-risks → 200 OK
  - [ ] GET /api/v1/analytics/summary → 200 OK with data
  - [ ] Check `device_risk_scores` table has records
  - [ ] Check `daily_analytics_rollups` table has records

### Scan Event Integration

- [ ] **Trigger Post-Scan Task**
  - [ ] When scan status → COMPLETED, queue `post_scan_analytics_task`
  - [ ] Pass: tenant_id, scan_id
  - [ ] Task automatically updates: risk scores, rollups, trends, cache

- [ ] **Test End-to-End**
  - [ ] Run a test scan
  - [ ] Check Celery worker logs for task execution
  - [ ] Verify risk_scores updated in database
  - [ ] Verify rollup generated for today
  - [ ] Refresh dashboard, see updated KPIs

### Frontend Setup

- [ ] **Deploy Analytics Dashboard**
  - [ ] Copy `analytics.html` to `frontend/` directory
  - [ ] Copy `analytics.css` to `frontend/css/` directory
  - [ ] Verify CSS loads: http://localhost:3000/css/analytics.css
  - [ ] Verify HTML loads: http://localhost:3000/analytics.html

- [ ] **Test Frontend Connections**
  - [ ] Open http://localhost:3000/analytics.html in browser
  - [ ] Check browser console for JavaScript errors
  - [ ] Verify API calls in Network tab:
    - [ ] GET /api/v1/analytics/summary → 200 OK
    - [ ] Response contains valid JSON with kpi, trends, top_devices
  - [ ] Test KPI cards display data
  - [ ] Test charts render (assume 30+ days of data for visible trends)
  - [ ] Test table populates with devices

- [ ] **Test Dashboard Features**
  - [ ] Time range selector (7/30/90 days) works
  - [ ] Refresh button updates data
  - [ ] Charts are interactive (hover shows tooltips)
  - [ ] Table is sortable by risk score
  - [ ] Mobile view is responsive (test on 480px width)

### Database & Performance

- [ ] **Create Indexes** (Production only)
  - [ ] Run: `scripts/create_analytics_indexes.sql`
  - [ ] Verify indexes created:
    ```sql
    SELECT name FROM sqlite_master WHERE type='index' AND name LIKE '%analytics%';
    ```

- [ ] **Monitor Query Performance**
  - [ ] Query /api/v1/analytics/summary
  - [ ] Response time should be <300ms
  - [ ] If >1s, check database queries (use EXPLAIN PLAN)

- [ ] **Backup Analytics Data**
  - [ ] Test daily rollup generation completes successfully
  - [ ] Monitor disk space for analytics tables growth

### Documentation & Operations

- [ ] **Review Documentation**
  - [ ] Read: `ANALYTICS_GUIDE.md`
  - [ ] Understand: Risk scoring algorithm
  - [ ] Understand: Data pipeline flow
  - [ ] Understand: API endpoints

- [ ] **Set Up Monitoring**
  - [ ] Monitor Celery task queue depth
  - [ ] Log Celery task failures
  - [ ] Alert if daily_maintenance task fails
  - [ ] Alert if risk scores haven't updated in 24h

- [ ] **Plan Rollout**
  - [ ] Alpha: Test with 1 test tenant
  - [ ] Beta: Test with 3-5 small customers
  - [ ] Production: Roll out to all tenants

---

## Verification Tests

### Test 1: API Health Check
```bash
curl http://localhost:5000/api/v1/analytics/health
# Expected: {"ok": true, "status": "healthy", "service": "analytics"}
```

### Test 2: KPI Summary (requires data)
```bash
curl -H "X-Tenant-ID: default" \
     -H "Authorization: Bearer token" \
     http://localhost:5000/api/v1/analytics/summary?days=7
# Expected: 200 OK with KPI data
```

### Test 3: Risk Calculation
```bash
curl -X POST \
     -H "X-Tenant-ID: default" \
     -H "Authorization: Bearer token" \
     http://localhost:5000/api/v1/analytics/calculate-risks
# Expected: {"ok": true, "data": {"devices_updated": N}}
```

### Test 4: Database Tables
```bash
sqlite3 instance/vapt_dev.db
> SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%analytics%';
> .tables

# Should show:
# daily_analytics_rollups
# device_risk_scores
# top_devices_analytics
# vulnerability_trends
```

### Test 5: Sample Data Generation
```bash
sqlite3 instance/vapt_dev.db
> SELECT COUNT(*) FROM device_risk_scores;
> SELECT COUNT(*) FROM daily_analytics_rollups;
> SELECT COUNT(*) FROM vulnerability_trends;

# All should have records > 0 after running setup_analytics.py
```

### Test 6: Celery Task Execution
```bash
# Start Celery worker in terminal
celery -A backend.celery_app worker -l debug -Q analytics

# In another terminal, trigger a task
python -c "
from backend.tasks.analytics_tasks import update_device_risks_task
from backend.celery_app import celery_app

result = update_device_risks_task.delay('default')
print(f'Task ID: {result.id}')
print(f'Result: {result.get(timeout=30)}')
"
```

---

## Troubleshooting

### Issue: 404 on /api/v1/analytics/summary
**Solution**: 
1. Verify blueprint registered in Flask app
2. Check Flask app initialization code
3. Test: `flask url_map` to list routes

### Issue: "X-Tenant-ID" header required
**Solution**: Add header to all requests:
```bash
curl -H "X-Tenant-ID: default" http://localhost:5000/api/v1/analytics/summary
```

### Issue: Empty trends data
**Solution**:
1. Ensure vulnerability_trends records exist
2. Run: `POST /api/v1/analytics/generate-rollup`
3. Check if scans have vulnerabilities

### Issue: Celery tasks not executing
**Solution**:
1. Verify Celery worker running: `celery -A backend.celery_app worker -l info`
2. Check Redis/RabbitMQ connection
3. Monitor Celery logs for errors
4. Test with: `celery -A backend.celery_app inspect active`

### Issue: Charts not rendering on dashboard
**Solution**:
1. Check browser console for JS errors
2. Verify API response in Network tab
3. Ensure Chart.js loads from CDN
4. Test with: curl /api/v1/analytics/summary

---

## Files Created/Modified

### New Files Created:
```
backend/core/analytics_models.py       (4 new models)
backend/core/analytics_service.py      (3 service classes)
backend/api/analytics.py               (7 API endpoints)
backend/tasks/analytics_tasks.py       (6 Celery tasks)
frontend/analytics.html                (Interactive dashboard)
frontend/css/analytics.css             (Dashboard styling)
ANALYTICS_GUIDE.md                     (Complete documentation)
setup_analytics.py                     (Auto-initialization)
```

### Files to Modify:
```
backend/enterprise/__init__.py         (Add blueprint registration)
backend/config.py                      (Add Celery queue)
backend/enterprise/tasks/scan_worker.py (Trigger post-scan task, if exists)
```

### Optional Files:
```
scripts/create_analytics_indexes.sql   (Performance indexes)
```

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| API Response Time | <300ms | Cached rollups + indexed queries |
| Dashboard Load | <2s | All data via single API call |
| Risk Calculation | <500ms per device | Async, background task |
| Daily Rollup | <10s | Once per day, all tenants |
| Memory Usage | <500MB | For analytics service |

---

## Rollout Plan

### Phase 1: Development (Current)
- [ ] All components tested locally
- [ ] SQLite database used
- [ ] Celery running in-process

### Phase 2: Staging
- [ ] Deploy to staging environment
- [ ] PostgreSQL database
- [ ] Redis message broker
- [ ] Full monitoring enabled
- [ ] Load test with 5+ years of sample data

### Phase 3: Production
- [ ] Deploy to production environment
- [ ] Enable database indexes
- [ ] Set up monitoring/alerting
- [ ] Create backup strategy
- [ ] Document runbook for operations team

---

## Success Criteria

✓ All API endpoints respond with 200 OK
✓ Risk scores calculated for all devices
✓ Daily rollups generate without errors
✓ Dashboard loads and displays KPIs
✓ Charts render with historical data
✓ Celery tasks execute post-scan
✓ Database queries complete <300ms
✓ All tests in "Verification Tests" section pass

---

**Last Updated**: March 28, 2026  
**Version**: 1.0  
**Estimated Setup Time**: 5-15 minutes  
**Support**: See ANALYTICS_GUIDE.md
