# DNS & Custom Domain Setup Guide

**Goal:** Point your domain to the CCTV VAPT application hosted on Render/Vercel

## Domain Registration

Register at one of these providers:
- **Namecheap** (cheap, easy)
- **GoDaddy** (popular)  
- **Route53** (AWS, integration with other AWS services)
- **Cloudflare** (includes free DNS + DDoS protection)
- **Google Domains** (simple interface)

**Example domain:** `vapt.yourcompany.com`

---

## DNS Configuration

### Full Setup (Recommended)

**1. Backend API (Render)**

Service: `api.vapt.yourcompany.com` → Render backend

```
Type     | Host              | Value
---------|-------------------|--------------------
CNAME    | api.vapt          | vapt-backend.onrender.com
```

**2. Frontend (Vercel)**

Service: `vapt.yourcompany.com` → Vercel frontend

```
Type     | Host              | Value
---------|-------------------|--------------------
CNAME    | vapt              | vapt-frontend.vercel.app
```

Or use root domain:

```
Type     | Host              | Value
---------|-------------------|--------------------
CNAME    | @                 | vapt-frontend.vercel.app
```

### DNS Provider Instructions

#### Namecheap

1. Login to Namecheap dashboard
2. Select domain → **Manage**
3. Navigate to **Advanced DNS**
4. Add CNAME records:
   - Host: `api.vapt`
   - Value: `vapt-backend.onrender.com`
   
   - Host: `vapt`
   - Value: `vapt-frontend.vercel.app`

5. Save changes (takes 5-30 minutes to propagate)

#### Route53 (AWS)

1. Go to Route53 console
2. Select your **Hosted Zone**
3. Click **Create record**
   - Name: `api.vapt.yourcompany.com`
   - Type: CNAME
   - Value: `vapt-backend.onrender.com`
   
4. Create another record
   - Name: `vapt.yourcompany.com`
   - Type: CNAME
   - Value: `vapt-frontend.vercel.app`

5. Click **Create records**

#### Cloudflare

1. Add domain to Cloudflare
2. Update nameservers at registrar to Cloudflare's nameservers
3. In Cloudflare dashboard → **DNS**
4. Add CNAME records:
   - Name: `api.vapt`
   - Content: `vapt-backend.onrender.com`
   - Proxy status: **Proxied** (optional - adds DDoS protection)
   
   - Name: `vapt`
   - Content: `vapt-frontend.vercel.app`
   - Proxy status: **DNS only** (Vercel handles SSL)

5. Save

---

## SSL/TLS Certificate Setup

### Render.com (Auto-provisioned)

- **Render automatically provisions SSL certificates from Let's Encrypt**
- No manual setup needed
- HTTPS automatically enabled for `api.vapt.yourcompany.com`

### Vercel.com (Auto-provisioned)

- **Vercel automatically provisions SSL certificates**
- No manual setup needed
- HTTPS automatically enabled for `vapt.yourcompany.com`

### Custom SSL (Optional - Advanced)

If using custom certificates:

1. **Generate certificate:**

```bash
# Using Let's Encrypt with Certbot
sudo certbot certonly --dns-cloudflare \
  -d vapt.yourcompany.com \
  -d api.vapt.yourcompany.com
```

2. **Upload to Render:**
   - Render Dashboard → Settings → SSL Certificate
   - Upload `.crt` and `.key` files

3. **Verify certificate:**

```bash
openssl x509 -in certificate.crt -text -noout
```

---

## DNS Verification & Testing

### Check DNS Resolution

```bash
# Linux/Mac
nslookup api.vapt.yourcompany.com
dig api.vapt.yourcompany.com
dig vapt.yourcompany.com

# Windows
nslookup api.vapt.yourcompany.com
```

**Expected output:**

```
api.vapt.yourcompany.com    CNAME   vapt-backend.onrender.com
vapt-backend.onrender.com   A       <IP-address>
```

### Test HTTPS Connection

```bash
# Test backend
curl -v https://api.vapt.yourcompany.com/health
# Expected: 200 OK with {"status": "healthy"}

# Test frontend
curl -v https://vapt.yourcompany.com
# Expected: 200 OK with HTML content
```

### SSL Certificate Validity

```bash
# Check certificate expiration
openssl s_client -connect api.vapt.yourcompany.com:443 -showcerts

# Or use curl
curl -vI https://api.vapt.yourcompany.com
```

---

## Email Subdomain (Optional)

If you want email @ your domain:

```
Type     | Host              | Value                  | Priority
---------|-------------------|------------------------|----------
MX       | @                 | mail.yourcompany.com   | 10
TXT      | @                 | <SPF-record>           | -
TXT      | _dmarc            | <DMARC-record>         | -
CNAME    | mail              | <email-provider>       | -
```

Example for Gmail:

```
MX    @    aspmx.l.google.com     5
MX    @    alt1.aspmx.l.google.com 10
...
TXT   @    v=spf1 include:_spf.google.com ~all
```

---

## Subdomain Routing Strategy

### Architecture with Subdomains

```
vapt.yourcompany.com             (Frontend - Vercel)
├── API backend served by proxy
└── WebSocket connections to api.vapt.yourcompany.com

api.vapt.yourcompany.com         (Backend API - Render)
├── REST endpoints: /api/v1/*
├── WebSocket: /ws/*
└── Health check: /health
```

### Environment Variables (Update)

**Frontend (.env or Vercel config):**

```env
REACT_APP_API_BASE_URL=https://api.vapt.yourcompany.com
REACT_APP_WS_URL=wss://api.vapt.yourcompany.com
```

**Backend (Environment variables):**

```env
CORS_ORIGINS=https://vapt.yourcompany.com,https://www.yourcompany.com
```

---

## DNS Propagation & Caching

### Time to Propagation

- **Global propagation:** 5 minutes to 48 hours
- **Typical:** 15-30 minutes
- **Check status:** https://www.whatsmydns.net

### Clear Local DNS Cache

**Windows:**

```bash
ipconfig /flushdns
```

**Mac:**

```bash
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

**Linux:**

```bash
sudo systemctl restart systemd-resolved
```

---

## CNAME vs A Records

| Record | Use Case | Value |
|--------|----------|-------|
| **CNAME** | Points to another domain | `vapt-backend.onrender.com` |
| **A** | Points to IP address | `192.0.2.1` |
| **AAAA** | IPv6 address | `2001:db8::1` |

**Note:** CNAME records cannot be used on the root domain `@`. Use A or ALIAS records instead.

---

## Troubleshooting DNS Issues

### Domain Not Resolving

```bash
# Check if DNS is propagated
nslookup api.vapt.yourcompany.com 8.8.8.8  # Google DNS

# Check DNS records
dig +trace api.vapt.yourcompany.com

# Check nameservers
whois vapt.yourcompany.com | grep -i nameserver
```

### HTTPS Certificate Not Trusted

- **Cause:** Certificate mismatch or not yet generated
- **Solution:** 
  1. Wait 5-15 minutes for Let's Encrypt to provision
  2. Access browser console: F12 → Console
  3. Clear browser cache: Ctrl+Shift+Delete
  4. Check certificate: https://crt.sh/?q=api.vapt.yourcompany.com

### Mixed Content Warning

- **Cause:** HTTP resources loaded on HTTPS page
- **Solution:** Update all API URLs to HTTPS in frontend

### CORS Errors After Domain Change

- **Cause:** CORS_ORIGINS not updated
- **Solution:** Update `CORS_ORIGINS=https://vapt.yourcompany.com` in backend env vars

---

## DNS Security (Optional)

### DNSSEC

Enable DNSSEC at your DNS provider to prevent DNS spoofing:

**Cloudflare:**
- Settings → DNSSEC → Enable DNSSEC

**Route53:**
- Hosted Zone → DNSSEC signing

### CAA Records (Certificate Authority Authorization)

Restrict which CAs can issue certificates for your domain:

```
Type  | Host | Value
------|------|------------------------------------------
CAA   | @    | 0 issue "letsencrypt.org"
CAA   | @    | 0 issuewild "letsencrypt.org"
CAA   | @    | 0 iodef "mailto:security@company.com"
```

---

## Monitoring DNS

### Monitor HTTPS Certificate Expiration

```bash
# Setup a reminder
echo "0 0 1 * * openssl s_client -connect api.vapt.yourcompany.com:443 -showcerts | grep -i notAfter" | crontab -
```

### Uptime Monitoring

Use services like:
- **Pingdom** - https://www.pingdom.com
- **StatusCake** - https://www.statuscake.com
- **UptimeRobot** - https://uptimerobot.com

### DNS Monitoring

- **DNSChecker** - https://dnschecker.org
- **Cloudflare Analytics** - Real-time DNS query logs

---

## Final Checklist

- [ ] Domain registered and nameservers updated
- [ ] CNAME records created for frontend (Vercel)
- [ ] CNAME records created for backend (Render)
- [ ] DNS propagation verified (`nslookup`)
- [ ] HTTPS certificates generated (green lock icon)
- [ ] Health check endpoint responds: `https://api.vapt.yourcompany.com/health`
- [ ] Frontend loads: `https://vapt.yourcompany.com`
- [ ] CORS origins updated in backend
- [ ] Frontend environment variables updated
- [ ] Email records configured (if needed)
- [ ] CAA records added (optional)
- [ ] Monitoring setup (Pingdom/StatusCake)

---

## Additional Resources

- [Namecheap CNAME Setup](https://www.namecheap.com/support/knowledgebase/article.aspx/9646/2237/how-do-i-set-up-host-records-for-a-domain/)
- [Route53 Routing Policies](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html)
- [Cloudflare DNS Docs](https://developers.cloudflare.com/dns/)
- [DNSSEC Best Practices](https://www.cloudflare.com/learning/dns/dnssec/)
- [Let's Encrypt Renewal](https://letsencrypt.org/docs/renewal/)
