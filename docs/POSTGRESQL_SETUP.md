# PostgreSQL Production Setup Guide

## Prerequisites

- PostgreSQL 12+ installed
- `psycopg2` Python driver (included in requirements.txt)
- Alembic for migrations

## 1. Create PostgreSQL User & Database

```sql
-- Connect to PostgreSQL as admin
psql -U postgres

-- Create application user
CREATE USER vapt_user WITH PASSWORD 'strong_password_here';

-- Create database
CREATE DATABASE vapt_prod OWNER vapt_user;

-- Grant permissions
GRANT CONNECT ON DATABASE vapt_prod TO vapt_user;
GRANT USAGE ON SCHEMA public TO vapt_user;
GRANT CREATE ON SCHEMA public TO vapt_user;

-- Exit psql
\q
```

## 2. Configure Environment Variables

Create `.env.production`:

```env
DATABASE_URL=postgresql://vapt_user:strong_password_here@localhost:5432/vapt_prod

# Or for remote PostgreSQL:
DATABASE_URL=postgresql://vapt_user:password@remote-host.com:5432/vapt_prod
```

## 3. Apply Migrations (Single-Tenant Schema)

```bash
cd backend
export DATABASE_URL=postgresql://vapt_user:password@host:5432/vapt_prod

# Run Alembic migrations
python -m alembic upgrade head

# Verify tables created
python -c "from backend.enterprise import create_app; app = create_app(); db.create_all()" 
```

## 4. Backup & Restore

### Backup Database

```bash
pg_dump -U vapt_user -h localhost -d vapt_prod > backup_2026-03-28.sql
```

### Restore from Backup

```bash
# Create new empty database
psql -U postgres -c "CREATE DATABASE vapt_prod_restore;"

# Restore data
psql -U vapt_user -d vapt_prod_restore < backup_2026-03-28.sql
```

## 5. Connection Pooling (Production)

For high-concurrency applications, use `pgBouncer`:

```bash
# Install pgBouncer
apt-get install pgbouncer

# Configure /etc/pgbouncer/pgbouncer.ini
[databases]
vapt_prod = host=localhost port=5432 dbname=vapt_prod

[pgbouncer]
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 25
reserve_pool_size = 5
reserve_pool_timeout = 3

# Start pgBouncer
systemctl start pgbouncer
```

Connection string becomes: `postgresql://vapt_user:password@localhost:6432/vapt_prod`

## 6. Monitoring & Maintenance

### Check Database Size

```sql
SELECT
    datname,
    pg_size_pretty(pg_database_size(datname)) AS size
FROM pg_database
WHERE datname = 'vapt_prod';
```

### Check Active Connections

```sql
SELECT
    pid,
    usename,
    application_name,
    state,
    query
FROM pg_stat_activity
WHERE datname = 'vapt_prod';
```

### Vacuum & Analyze (Regular maintenance)

```bash
# Full vacuum (locks table, run during maintenance window)
VACUUM FULL ANALYZE;

# Or regular maintenance
VACUUM;
ANALYZE;
```

## 7. Performance Tuning

### Auto-Vacuum Settings

```sql
ALTER TABLE scans SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.005
);
```

### Index Statistics

```sql
-- Rebuild indexes
REINDEX INDEX idx_scans_created_at;

-- Check index usage
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
```

## 8. SSL/TLS Connection (Recommended)

### With SSL Certificate

```env
DATABASE_URL=postgresql://vapt_user:password@host:5432/vapt_prod?sslmode=require
```

### Generate Self-Signed Cert (for testing)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## 9. Docker PostgreSQL (Local Development)

```bash
docker run -d \
  --name vapt-postgres \
  -e POSTGRES_USER=vapt_user \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=vapt_prod \
  -p 5432:5432 \
  -v vapt_pgdata:/var/lib/postgresql/data \
  postgres:15

# Connect
export DATABASE_URL=postgresql://vapt_user:password@localhost:5432/vapt_prod
```

## 10. Managed PostgreSQL Services

### Render.com

1. Create PostgreSQL instance
2. Copy `External Database URL`
3. Set `DATABASE_URL` environment variable

### AWS RDS

1. Create RDS PostgreSQL instance
2. Note endpoint: `vapt-prod.xxxxx.us-east-1.rds.amazonaws.com`
3. Set security groups to allow inbound 5432

### DigitalOcean

1. Create Managed Database
2. Copy connection string
3. Add to deployment environment

## Troubleshooting

### Connection Refused

```
Error: could not connect to database
```

- Check PostgreSQL is running: `systemctl status postgresql`
- Verify credentials: `psql -U vapt_user -h localhost`
- Check firewall: `sudo ufw allow 5432/tcp`

### Out of Memory

```sql
-- Check memory usage
SELECT
    query,
    query_start,
    state,
    backend_memory_contexts
FROM pg_stat_activity
WHERE query IS NOT NULL
ORDER BY query_start;
```

### Lock Timeout

```sql
-- Check locks
SELECT
    pid,
    usename,
    application_name,
    state,
    wait_event
FROM pg_stat_activity
WHERE wait_event IS NOT NULL;
```

## Additional Resources

- [PostgreSQL Official Docs](https://www.postgresql.org/docs/)
- [pgBouncer Documentation](https://www.pgbouncer.org/)
- [Render Database Guide](https://render.com/docs/postgres)
- [AWS RDS Best Practices](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/)
