"""
VAPT Tool - Main Application
Vulnerability Assessment & Penetration Testing for CCTV/DVR Systems
"""

import os
import json
import uuid
import logging
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit

# Import modules
from config import Config, config_by_name
from database.models import db, Scan, Device, Port, Vulnerability, AuditLog, Report
from modules.network_scanner import NetworkScanner
from modules.device_identifier import DeviceIdentifier
from modules.port_scanner import PortScanner
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.report_generator import ReportGenerator
import ipaddress
from flask import current_app


# Simple idempotency decorator (no-op for standalone app)
def idempotency_required(fn):
    """Simple idempotency decorator - no-op for standalone app"""
    return fn


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(config_by_name.get(os.environ.get("FLASK_ENV", "development")))

# Initialize extensions
CORS(app, origins=["*"])
# On Windows, eventlet may have compatibility issues — prefer threading there.
if os.name == "nt":
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
else:
    try:
        import eventlet  # noqa: F401

        socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
    except Exception:
        socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
db.init_app(app)

# Initialize directories
Config.init_directories()

# Create database tables
with app.app_context():
    db.create_all()

# Initialize scanner modules
network_scanner = NetworkScanner()
device_identifier = DeviceIdentifier()
port_scanner = PortScanner()
vulnerability_scanner = VulnerabilityScanner()
report_generator = ReportGenerator(str(Config.REPORTS_DIR))


def audit_log(action: str):
    """Decorator to log all actions for audit trail"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Create audit log entry
            log_entry = AuditLog(
                timestamp=datetime.utcnow(),
                operator=(
                    request.json.get("operator_name", "unknown")
                    if request.json
                    else "unknown"
                ),
                action=action,
                target=request.path,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                status="initiated",
            )

            try:
                result = f(*args, **kwargs)
                log_entry.status = "success"
                db.session.add(log_entry)
                db.session.commit()
                return result
            except Exception as e:
                log_entry.status = "error"
                log_entry.error_message = str(e)
                db.session.add(log_entry)
                db.session.commit()
                raise

        return decorated_function

    return decorator


# =============================================================================
# Frontend Routes
# =============================================================================


@app.route("/", methods=["GET"])
def index():
    """Serve the main frontend page"""
    frontend_path = os.path.join(
        os.path.dirname(__file__), "..", "frontend", "index.html"
    )
    return send_file(frontend_path)


# =============================================================================
# Static File Routes (Frontend Assets)
# =============================================================================

@app.route("/css/<path:filename>", methods=["GET"])
def serve_css(filename):
    """Serve CSS files from frontend/css directory"""
    css_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "css", filename)
    return send_file(css_path)


@app.route("/js/<path:filename>", methods=["GET"])
def serve_js(filename):
    """Serve JS files from frontend/js directory"""
    js_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "js", filename)
    return send_file(js_path)


# =============================================================================
# API Routes
# =============================================================================


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": Config.APP_VERSION,
        }
    )


@app.route("/api/network/info", methods=["GET"])
def get_network_info():
    """Get local network information"""
    try:
        network_info = network_scanner.get_local_network_info()
        return jsonify({"success": True, "data": network_info})
    except Exception as e:
        logger.error(f"Failed to get network info: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/scan/start", methods=["POST"])
@audit_log("scan_started")
@idempotency_required
def start_scan():
    data = request.get_json() or {}
    operator_name = (data.get("operator_name") or "").strip()
    network_range = (data.get("network_range") or "").strip()
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    if not operator_name:
        return (
            jsonify(
                {
                    "success": False,
                    "data": None,
                    "error": {"code": "operator.missing", "message": "Operator name is required"},
                    "request_id": request_id,
                }
            ),
            400,
        )

    if len(operator_name) > 100:
        return (
            jsonify(
                {
                    "success": False,
                    "data": None,
                    "error": {"code": "operator.invalid", "message": "Operator name too long"},
                    "request_id": request_id,
                }
            ),
            400,
        )

    if network_range:
        try:
            ipaddress.ip_network(network_range, strict=False)
        except Exception:
            return (
                jsonify(
                    {
                        "success": False,
                        "data": None,
                        "error": {"code": "network.invalid", "message": "Invalid network_range"},
                        "request_id": request_id,
                    }
                ),
                400,
            )

    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"

    try:
        scan = Scan(
            scan_id=scan_id,
            operator_name=operator_name,
            status="pending",
            network_range=network_range or None,
            started_at=datetime.utcnow(),
        )
        db.session.add(scan)
        db.session.flush()

        if not network_range:
            network_info = network_scanner.get_local_network_info()
            inferred = network_info.get("network")
            if inferred:
                scan.network_range = inferred

        scan.status = "running"
        db.session.commit()

        socketio.start_background_task(
            execute_scan, app.app_context(), scan.id, scan_id, scan.network_range, operator_name
        )

        return (
            jsonify(
                {
                    "success": True,
                    "data": {"scan_id": scan_id, "status": "running"},
                    "error": None,
                    "request_id": request_id,
                }
            ),
            202,
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to start scan: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "data": None,
                    "error": {"code": "scan.create_failed", "message": str(e)},
                    "request_id": request_id,
                }
            ),
            500,
        )




@app.route("/api/scan/demo", methods=["POST"])
def start_demo_scan():
    """Start a demo scan with simulated CCTV devices for presentation purposes"""
    import time

    scan_id = f"DEMO-{uuid.uuid4().hex[:8].upper()}"
    request_id = str(uuid.uuid4())

    try:
        scan = Scan(
            scan_id=scan_id,
            operator_name="Demo User",
            status="running",
            scan_type="network_discovery",
            network_range="192.168.1.0/24 (Demo)",
            started_at=datetime.utcnow(),
        )
        db.session.add(scan)
        db.session.flush()
        db_scan_id = scan.id
        db.session.commit()

        socketio.start_background_task(_run_demo_scan, app.app_context(), db_scan_id, scan_id)

        return (
            jsonify(
                {
                    "success": True,
                    "data": {"scan_id": scan_id, "status": "running"},
                    "error": None,
                    "request_id": request_id,
                }
            ),
            202,
        )
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to start demo scan: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "data": None,
                    "error": {"code": "demo.create_failed", "message": "Failed to start demo scan"},
                    "request_id": request_id,
                }
            ),
            500,
        )


def _run_demo_scan(app_context, db_scan_id: int, scan_id: str):
    """Run the demo scan simulation with realistic delays and Socket.IO events"""
    import time

    with app_context:
        try:
            scan = Scan.query.get(db_scan_id)
            if not scan:
                return

            # --- Demo device definitions ---
            demo_devices = [
                {
                    "ip": "192.168.1.1",
                    "hostname": "router.local",
                    "manufacturer": "TP-Link",
                    "device_type": "router",
                    "model": "Archer C7",
                    "is_cctv": False,
                    "ports": [(80, "http"), (443, "https"), (22, "ssh")],
                    "vulns": [],
                },
                {
                    "ip": "192.168.1.10",
                    "hostname": "HIK-DVR-01",
                    "manufacturer": "Hikvision",
                    "device_type": "dvr",
                    "model": "DS-7208HQHI-K2",
                    "is_cctv": True,
                    "ports": [
                        (80, "http"),
                        (443, "https"),
                        (554, "rtsp"),
                        (8000, "hikvision-sdk"),
                        (8200, "hikvision-web"),
                    ],
                    "vulns": [
                        {
                            "vuln_id": "CCTV-001",
                            "title": "Default Credentials Active",
                            "description": "Device uses factory default username/password (admin/12345). Attackers can gain full administrative access.",
                            "severity": "critical",
                            "cvss_score": 9.8,
                            "cve_id": "CVE-2017-7921",
                            "remediation": "Change default credentials immediately. Use a strong unique password.",
                        },
                        {
                            "vuln_id": "CCTV-002",
                            "title": "RTSP Stream Unauthenticated",
                            "description": "The RTSP video stream on port 554 is accessible without authentication, exposing live camera footage.",
                            "severity": "high",
                            "cvss_score": 7.5,
                            "cve_id": None,
                            "remediation": "Enable RTSP authentication in device settings.",
                        },
                        {
                            "vuln_id": "CCTV-003",
                            "title": "Firmware Information Disclosure",
                            "description": "HTTP response headers expose firmware version details that aid targeted exploitation.",
                            "severity": "medium",
                            "cvss_score": 5.3,
                            "cve_id": None,
                            "remediation": "Disable verbose HTTP headers or update firmware.",
                        },
                    ],
                },
                {
                    "ip": "192.168.1.15",
                    "hostname": "DAHUA-NVR-01",
                    "manufacturer": "Dahua",
                    "device_type": "nvr",
                    "model": "NVR4108-P-4KS2",
                    "is_cctv": True,
                    "ports": [
                        (80, "http"),
                        (554, "rtsp"),
                        (37777, "dahua-sdk"),
                        (37778, "dahua-web"),
                    ],
                    "vulns": [
                        {
                            "vuln_id": "CCTV-001",
                            "title": "Default Credentials Active",
                            "description": "Device uses factory default username/password (admin/admin). Full administrative access is trivially obtainable.",
                            "severity": "critical",
                            "cvss_score": 9.8,
                            "cve_id": "CVE-2021-33044",
                            "remediation": "Change default credentials immediately.",
                        },
                        {
                            "vuln_id": "CCTV-004",
                            "title": "Telnet Service Enabled",
                            "description": "Telnet (port 23) is enabled, transmitting credentials in plaintext over the network.",
                            "severity": "high",
                            "cvss_score": 7.2,
                            "cve_id": None,
                            "remediation": "Disable Telnet. Use SSH for remote management.",
                        },
                        {
                            "vuln_id": "CCTV-005",
                            "title": "HTTP Without HTTPS Redirect",
                            "description": "Web interface is accessible over unencrypted HTTP on port 80 with no redirect to HTTPS.",
                            "severity": "medium",
                            "cvss_score": 5.0,
                            "cve_id": None,
                            "remediation": "Enable HTTPS and redirect all HTTP traffic to HTTPS.",
                        },
                    ],
                },
                {
                    "ip": "192.168.1.20",
                    "hostname": "LAPTOP-USER",
                    "manufacturer": "Dell",
                    "device_type": "laptop",
                    "model": "Inspiron 15",
                    "is_cctv": False,
                    "ports": [(445, "smb"), (135, "msrpc")],
                    "vulns": [],
                },
                {
                    "ip": "192.168.1.25",
                    "hostname": "AXIS-CAM-01",
                    "manufacturer": "Axis",
                    "device_type": "camera",
                    "model": "P3245-V",
                    "is_cctv": True,
                    "ports": [(80, "http"), (443, "https"), (554, "rtsp")],
                    "vulns": [
                        {
                            "vuln_id": "CCTV-002",
                            "title": "RTSP Stream Unauthenticated",
                            "description": "RTSP stream accessible without authentication on port 554.",
                            "severity": "high",
                            "cvss_score": 7.5,
                            "cve_id": None,
                            "remediation": "Enable RTSP authentication in camera settings.",
                        },
                        {
                            "vuln_id": "CCTV-006",
                            "title": "Missing Security Headers",
                            "description": "HTTP responses lack security headers (X-Frame-Options, CSP, HSTS), increasing risk of clickjacking.",
                            "severity": "low",
                            "cvss_score": 3.1,
                            "cve_id": None,
                            "remediation": "Configure the web server to include recommended security headers.",
                        },
                    ],
                },
                {
                    "ip": "192.168.1.30",
                    "hostname": "android-phone",
                    "manufacturer": "Samsung",
                    "device_type": "mobile",
                    "model": "Galaxy S21",
                    "is_cctv": False,
                    "ports": [(8080, "http-alt")],
                    "vulns": [],
                },
            ]

            total_steps = len(demo_devices) + 2  # discovery + per-device + completion
            step = 0

            # Phase 1: Discovery
            socketio.emit("scan_progress", {
                "scan_id": scan_id, "phase": "discovery", "progress": 0,
                "message": "Starting network discovery on 192.168.1.0/24...",
            })
            time.sleep(1.5)

            for dev in demo_devices:
                step += 1
                progress = int((step / total_steps) * 40)
                socketio.emit("scan_progress", {
                    "scan_id": scan_id, "phase": "discovery", "progress": progress,
                    "message": f"Discovered host: {dev['ip']}",
                    "host": {"ip_address": dev["ip"], "hostname": dev.get("hostname", "")},
                })
                time.sleep(0.6)

            scan.total_hosts_found = len(demo_devices)
            db.session.commit()

            # Phase 2: Port scanning
            socketio.emit("scan_progress", {
                "scan_id": scan_id, "phase": "ports", "progress": 40,
                "message": "Starting port scan on discovered hosts...",
            })
            time.sleep(1.0)

            cctv_count = 0
            total_vulns = 0
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            for idx, dev in enumerate(demo_devices):
                port_progress = 40 + int(((idx + 1) / len(demo_devices)) * 30)
                socketio.emit("scan_progress", {
                    "scan_id": scan_id, "phase": "ports", "progress": port_progress,
                    "message": f"Scanning ports on {dev['ip']}...",
                })

                device = Device(
                    scan_id=db_scan_id,
                    ip_address=dev["ip"],
                    hostname=dev.get("hostname"),
                    manufacturer=dev.get("manufacturer"),
                    device_type=dev.get("device_type"),
                    model=dev.get("model"),
                    is_cctv=dev["is_cctv"],
                    confidence_score=0.95 if dev["is_cctv"] else 0.3,
                    discovered_at=datetime.utcnow(),
                )
                db.session.add(device)
                db.session.flush()

                for port_num, svc_name in dev["ports"]:
                    port = Port(
                        device_id=device.id,
                        port_number=port_num,
                        protocol="tcp",
                        state="open",
                        service_name=svc_name,
                    )
                    db.session.add(port)

                if dev["is_cctv"]:
                    cctv_count += 1

                time.sleep(0.5)

            db.session.commit()

            # Phase 3: Vulnerability scanning
            socketio.emit("scan_progress", {
                "scan_id": scan_id, "phase": "vulnerability", "progress": 70,
                "message": "Scanning CCTV devices for vulnerabilities...",
            })
            time.sleep(1.0)

            # Re-query devices to attach vulnerabilities
            db_devices = Device.query.filter_by(scan_id=db_scan_id).all()
            ip_to_db_device = {d.ip_address: d for d in db_devices}

            for idx, dev in enumerate(demo_devices):
                vuln_progress = 70 + int(((idx + 1) / len(demo_devices)) * 25)
                socketio.emit("scan_progress", {
                    "scan_id": scan_id, "phase": "vulnerability", "progress": vuln_progress,
                    "message": f"Checking vulnerabilities on {dev['ip']}...",
                })

                db_dev = ip_to_db_device.get(dev["ip"])
                if db_dev:
                    for vuln_info in dev["vulns"]:
                        vuln = Vulnerability(
                            device_id=db_dev.id,
                            vuln_id=vuln_info["vuln_id"],
                            title=vuln_info["title"],
                            description=vuln_info["description"],
                            severity=vuln_info["severity"],
                            cvss_score=vuln_info.get("cvss_score"),
                            cve_id=vuln_info.get("cve_id"),
                            remediation=vuln_info.get("remediation"),
                            references=json.dumps([]),
                        )
                        db.session.add(vuln)
                        total_vulns += 1
                        sev = vuln_info["severity"]
                        if sev in severity_counts:
                            severity_counts[sev] += 1

                time.sleep(0.4)

            db.session.commit()

            # Finalize scan record
            scan.cctv_devices_found = cctv_count
            scan.vulnerabilities_found = total_vulns
            scan.critical_count = severity_counts["critical"]
            scan.high_count = severity_counts["high"]
            scan.medium_count = severity_counts["medium"]
            scan.low_count = severity_counts["low"]
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            db.session.commit()

            socketio.emit("scan_complete", {
                "scan_id": scan_id,
                "status": "completed",
                "summary": scan.to_dict(),
            })
            logger.info(f"Demo scan {scan_id} completed successfully")

        except Exception as e:
            logger.error(f"Demo scan {scan_id} failed: {e}")
            try:
                scan = Scan.query.get(db_scan_id)
                if scan:
                    scan.status = "failed"
                    scan.error_message = str(e)
                    scan.completed_at = datetime.utcnow()
                    db.session.commit()
            except Exception:
                pass
            socketio.emit("scan_error", {"scan_id": scan_id, "error": str(e)})


def execute_scan(
    app_context, db_scan_id: int, scan_id: str, network_range: str, operator: str
):
    """Execute the full scan pipeline with fault tolerance"""
    with app_context:
        scan = None
        try:
            scan = Scan.query.get(db_scan_id)
            if not scan:
                raise ValueError(f"Scan {db_scan_id} not found in database")

            # Phase 1: Network Discovery
            socketio.emit(
                "scan_progress",
                {
                    "scan_id": scan_id,
                    "phase": "discovery",
                    "progress": 0,
                    "message": "Starting network discovery...",
                },
            )

            def discovery_callback(data):
                socketio.emit(
                    "scan_progress",
                    {
                        "scan_id": scan_id,
                        "phase": "discovery",
                        "progress": data.get("progress", 0),
                        "message": f"Discovered host: {data.get('host', {}).get('ip_address', '')}",
                    },
                )

            try:
                hosts = network_scanner.scan_network_arp(
                    network_range, discovery_callback
                )
                scan.total_hosts_found = len(hosts)
                db.session.commit()
            except Exception as e:
                logger.error(f"Network discovery failed: {e}")
                socketio.emit(
                    "scan_progress",
                    {
                        "scan_id": scan_id,
                        "phase": "discovery",
                        "progress": 100,
                        "message": f"Network discovery failed: {e}",
                    },
                )
                hosts = []  # Continue with empty host list

            socketio.emit(
                "scan_progress",
                {
                    "scan_id": scan_id,
                    "phase": "discovery",
                    "progress": 100,
                    "message": f"Found {len(hosts)} hosts",
                },
            )

            # Phase 2: Device Identification
            socketio.emit(
                "scan_progress",
                {
                    "scan_id": scan_id,
                    "phase": "identification",
                    "progress": 0,
                    "message": "Identifying CCTV devices...",
                },
            )

            cctv_devices = []
            ports_data = {}
            banners_data = {}

            for idx, host in enumerate(hosts):
                ip = host.get("ip_address")
                if not ip:
                    continue

                try:
                    # Port scan
                    port_result = port_scanner.scan_host(ip)
                    ports_data[ip] = port_result.get("open_ports", [])
                    banners_data[ip] = port_result.get("banners", {})
                except Exception as e:
                    logger.debug(f"Port scan failed for {ip}: {e}")
                    ports_data[ip] = []
                    banners_data[ip] = {}

                progress = ((idx + 1) / len(hosts)) * 100 if hosts else 0
                socketio.emit(
                    "scan_progress",
                    {
                        "scan_id": scan_id,
                        "phase": "identification",
                        "progress": progress,
                        "message": f"Scanning {ip}...",
                    },
                )

            # Identify devices
            try:
                identified = device_identifier.bulk_identify(
                    hosts, ports_data, banners_data
                )
                cctv_devices = device_identifier.filter_cctv_devices(identified)
            except Exception as e:
                logger.error(f"Device identification failed: {e}")
                identified = hosts  # Fallback to basic host info
                cctv_devices = []

            scan.cctv_devices_found = len(cctv_devices)
            db.session.commit()

            socketio.emit(
                "scan_progress",
                {
                    "scan_id": scan_id,
                    "phase": "identification",
                    "progress": 100,
                    "message": f"Identified {len(cctv_devices)} CCTV devices",
                },
            )

            # Phase 3: Vulnerability Scanning
            socketio.emit(
                "scan_progress",
                {
                    "scan_id": scan_id,
                    "phase": "vulnerability",
                    "progress": 0,
                    "message": "Scanning for vulnerabilities...",
                },
            )

            total_vulns = 0
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            for idx, device_info in enumerate(identified):
                ip = device_info.get("ip_address")
                if not ip:
                    continue

                try:
                    # Create device record
                    device = Device(
                        scan_id=scan.id,
                        ip_address=ip,
                        mac_address=device_info.get("mac_address"),
                        manufacturer=device_info.get("manufacturer"),
                        device_type=device_info.get("device_type"),
                        is_cctv=device_info.get("is_cctv", False),
                        confidence_score=device_info.get("confidence_score", 0),
                    )
                    db.session.add(device)
                    db.session.flush()

                    # Add ports
                    for port_info in ports_data.get(ip, []):
                        port = Port(
                            device_id=device.id,
                            port_number=port_info.get("port_number"),
                            protocol=port_info.get("protocol", "tcp"),
                            state=port_info.get("state", "open"),
                            service_name=port_info.get("service_name"),
                            banner=port_info.get("banner"),
                        )
                        db.session.add(port)

                    # Vulnerability scan for CCTV devices
                    if device_info.get("is_cctv"):
                        try:
                            vuln_result = vulnerability_scanner.scan_device(
                                device_info, ports_data.get(ip, []), deep_scan=True
                            )

                            for vuln_info in vuln_result.get("vulnerabilities", []):
                                vuln = Vulnerability(
                                    device_id=device.id,
                                    vuln_id=vuln_info.get("vuln_id"),
                                    title=vuln_info.get("title"),
                                    description=vuln_info.get("description"),
                                    severity=vuln_info.get("severity"),
                                    cvss_score=vuln_info.get("cvss_score"),
                                    cve_id=vuln_info.get("cve_id"),
                                    cwe_id=vuln_info.get("cwe_id"),
                                    remediation=vuln_info.get("remediation"),
                                    proof_of_concept=vuln_info.get("proof_of_concept"),
                                    references=json.dumps(
                                        vuln_info.get("references", [])
                                    ),
                                )
                                db.session.add(vuln)

                                total_vulns += 1
                                sev = vuln_info.get("severity", "low")
                                if sev in severity_counts:
                                    severity_counts[sev] += 1
                        except Exception as e:
                            logger.debug(f"Vulnerability scan failed for {ip}: {e}")
                            # Continue without failing the entire scan

                except Exception as e:
                    logger.error(f"Device processing failed for {ip}: {e}")
                    continue

                progress = ((idx + 1) / len(identified)) * 100 if identified else 0
                socketio.emit(
                    "scan_progress",
                    {
                        "scan_id": scan_id,
                        "phase": "vulnerability",
                        "progress": progress,
                        "message": f"Scanning {ip} for vulnerabilities...",
                    },
                )

            # Update scan record
            scan.vulnerabilities_found = total_vulns
            scan.critical_count = severity_counts["critical"]
            scan.high_count = severity_counts["high"]
            scan.medium_count = severity_counts["medium"]
            scan.low_count = severity_counts["low"]
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            db.session.commit()

            # Emit completion
            socketio.emit(
                "scan_complete",
                {"scan_id": scan_id, "status": "completed", "summary": scan.to_dict()},
            )

            logger.info(f"Scan {scan_id} completed successfully")

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                db.session.commit()

            socketio.emit("scan_error", {"scan_id": scan_id, "error": str(e)})


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    """Get scan details"""
    scan = Scan.query.filter_by(scan_id=scan_id).first()

    if not scan:
        return jsonify({"success": False, "error": "Scan not found"}), 404

    return jsonify({"success": True, "data": scan.to_dict()})


@app.route("/api/scan/<scan_id>/devices", methods=["GET"])
def get_scan_devices(scan_id):
    """Get devices discovered in a scan"""
    scan = Scan.query.filter_by(scan_id=scan_id).first()

    if not scan:
        return jsonify({"success": False, "error": "Scan not found"}), 404

    devices = [device.to_dict() for device in scan.devices]

    return jsonify(
        {
            "success": True,
            "data": {"scan_id": scan_id, "devices": devices, "total": len(devices)},
        }
    )


@app.route("/api/device/<int:device_id>/detailed-scan", methods=["POST"])
@audit_log("detailed_scan")
def detailed_device_scan(device_id):
    """Perform detailed port and vulnerability scan on a device"""
    device = Device.query.get(device_id)

    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404

    try:
        scan_result = {
            "device_id": device.id,
            "ip_address": device.ip_address,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "port_scan": {},
            "vulnerability_scan": {},
            "risk_summary": {}
        }

        # 1. Perform port scan
        logger.info(f"Starting detailed scan for {device.ip_address}")
        port_scan_result = port_scanner.scan_host(device.ip_address)
        scan_result["port_scan"] = port_scan_result

        # Update ports in database
        Port.query.filter_by(device_id=device.id).delete()
        open_ports = port_scan_result.get("open_ports", [])

        for port_info in open_ports:
            port = Port(
                device_id=device.id,
                port_number=port_info.get("port_number"),
                protocol=port_info.get("protocol", "tcp"),
                state=port_info.get("state", "open"),
                service_name=port_info.get("service_name"),
                banner=port_info.get("banner"),
                scanned_at=datetime.utcnow()
            )
            db.session.add(port)

        # 2. Perform vulnerability scan on open ports
        if open_ports:
            vuln_result = vulnerability_scanner.scan_device(device.to_dict(), [p.to_dict() for p in device.ports], deep_scan=True)
            scan_result["vulnerability_scan"] = vuln_result

            # Update vulnerabilities in database
            Vulnerability.query.filter_by(device_id=device.id).delete()

            for vuln_info in vuln_result.get("vulnerabilities", []):
                vuln = Vulnerability(
                    device_id=device.id,
                    vuln_id=vuln_info.get("vuln_id"),
                    title=vuln_info.get("title"),
                    description=vuln_info.get("description"),
                    severity=vuln_info.get("severity"),
                    cvss_score=vuln_info.get("cvss_score"),
                    cve_id=vuln_info.get("cve_id"),
                    cwe_id=vuln_info.get("cwe_id"),
                    remediation=vuln_info.get("remediation"),
                    proof_of_concept=vuln_info.get("proof_of_concept"),
                    references=json.dumps(vuln_info.get("references", [])),
                    discovered_at=datetime.utcnow()
                )
                db.session.add(vuln)

        # 3. Generate risk summary
        port_data = {
            "rtsp_open": 554 in [p.get("port_number") for p in open_ports],
            "web_exposed": any(p.get("port_number") in [80, 8080, 443, 8443] for p in open_ports),
            "dahua_detected": 37777 in [p.get("port_number") for p in open_ports],
            "hikvision_detected": 8000 in [p.get("port_number") for p in open_ports],
            "ssh_telnet_open": any(p.get("port_number") in [22, 23] for p in open_ports),
        }

        vulnerabilities = scan_result["vulnerability_scan"].get("vulnerabilities", [])
        risk_summary = {
            "total_open_ports": len(open_ports),
            "total_vulnerabilities": len(vulnerabilities),
            "critical_vulns": len([v for v in vulnerabilities if v.get("severity", "").lower() == "critical"]),
            "high_vulns": len([v for v in vulnerabilities if v.get("severity", "").lower() == "high"]),
            "medium_vulns": len([v for v in vulnerabilities if v.get("severity", "").lower() == "medium"]),
            "low_vulns": len([v for v in vulnerabilities if v.get("severity", "").lower() == "low"]),
            "port_risks": port_data,
            "risk_level": calculate_risk_level(port_data, vulnerabilities)
        }

        scan_result["risk_summary"] = risk_summary

        db.session.commit()

        return jsonify({
            "success": True,
            "data": scan_result
        })

    except Exception as e:
        logger.error(f"Detailed scan failed for device {device_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


def calculate_risk_level(port_data, vulnerabilities):
    """Calculate overall risk level based on ports and vulnerabilities"""
    risk_score = 0
    
    # Port-based risk
    if port_data.get("rtsp_open"):
        risk_score += 3
    if port_data.get("web_exposed"):
        risk_score += 2
    if port_data.get("ssh_telnet_open"):
        risk_score += 2
    
    # Vulnerability-based risk
    critical = len([v for v in vulnerabilities if v.get("severity", "").lower() == "critical"])
    high = len([v for v in vulnerabilities if v.get("severity", "").lower() == "high"])
    
    risk_score += (critical * 3) + (high * 1)
    
    # Determine level
    if risk_score >= 8:
        return "CRITICAL"
    elif risk_score >= 5:
        return "HIGH"
    elif risk_score >= 3:
        return "MEDIUM"
    elif risk_score > 0:
        return "LOW"
    else:
        return "NONE"


@app.route("/api/device/<int:device_id>/scan-ports", methods=["POST"])
@audit_log("port_scan")
def scan_device_ports(device_id):
    """Scan ports for a specific device"""
    device = Device.query.get(device_id)

    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404

    try:
        result = port_scanner.scan_host(device.ip_address)

        # Update device ports in database
        Port.query.filter_by(device_id=device.id).delete()

        for port_info in result.get("open_ports", []):
            port = Port(
                device_id=device.id,
                port_number=port_info.get("port_number"),
                protocol=port_info.get("protocol", "tcp"),
                state=port_info.get("state", "open"),
                service_name=port_info.get("service_name"),
                banner=port_info.get("banner"),
            )
            db.session.add(port)

        db.session.commit()

        return jsonify({"success": True, "data": result})

    except Exception as e:
        logger.error(f"Port scan failed for device {device_id}: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/device/<int:device_id>/scan-vulnerabilities", methods=["POST"])
@audit_log("vulnerability_scan")
def scan_device_vulnerabilities(device_id):
    """Scan vulnerabilities for a specific device"""
    device = Device.query.get(device_id)

    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404

    try:
        # Get device ports
        ports = [port.to_dict() for port in device.ports]

        # Scan for vulnerabilities
        result = vulnerability_scanner.scan_device(
            device.to_dict(), ports, deep_scan=True
        )

        # Update vulnerabilities in database
        Vulnerability.query.filter_by(device_id=device.id).delete()

        for vuln_info in result.get("vulnerabilities", []):
            vuln = Vulnerability(
                device_id=device.id,
                vuln_id=vuln_info.get("vuln_id"),
                title=vuln_info.get("title"),
                description=vuln_info.get("description"),
                severity=vuln_info.get("severity"),
                cvss_score=vuln_info.get("cvss_score"),
                cve_id=vuln_info.get("cve_id"),
                cwe_id=vuln_info.get("cwe_id"),
                remediation=vuln_info.get("remediation"),
                proof_of_concept=vuln_info.get("proof_of_concept"),
                references=json.dumps(vuln_info.get("references", [])),
            )
            db.session.add(vuln)

        db.session.commit()

        return jsonify({"success": True, "data": result})

    except Exception as e:
        logger.error(f"Vulnerability scan failed for device {device_id}: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/scan/<scan_id>/report", methods=["POST"])
@audit_log("report_generated")
def generate_report(scan_id):
    """Generate comprehensive report for a scan using 6-layer pipeline"""
    from reporting_engine import ReportOrchestrator, OutputDistributor
    
    try:
        # Try parsing as integer ID first, then as string scan_id
        try:
            scan = Scan.query.filter_by(id=int(scan_id)).first()
        except (ValueError, TypeError):
            scan = Scan.query.filter_by(scan_id=scan_id).first()

        if not scan:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        if scan.status != "completed":
            return jsonify({"success": False, "error": "Scan not completed yet"}), 400

        # Prepare scan data for reporting pipeline
        scan_data = {
            "scan_id": scan.id,
            "operator_name": scan.operator_name or "Unknown",
            "network_range": scan.network_range,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "status": scan.status,
            "total_hosts_found": scan.total_hosts_found or 0,
            "cctv_devices_found": scan.cctv_devices_found or 0,
            "vulnerabilities_found": scan.vulnerabilities_found or 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "devices": []
        }

        # Serialize devices
        for device in scan.devices:
            device_data = {
                "id": device.id,
                "ip_address": device.ip_address,
                "mac_address": device.mac_address,
                "manufacturer": device.manufacturer,
                "device_type": device.device_type,
                "is_cctv": device.is_cctv,
                "confidence_score": device.confidence_score,
                "ports": [],
                "vulnerabilities": []
            }

            # Add ports
            for port in device.ports:
                device_data["ports"].append({
                    "port_number": port.port_number,
                    "protocol": port.protocol,
                    "service_name": port.service_name,
                    "banner": port.banner
                })

            # Add vulnerabilities and count by severity
            for vuln in device.vulnerabilities:
                vuln_data = {
                    "id": vuln.id,
                    "vuln_id": vuln.vuln_id,
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "severity": vuln.severity,
                    "cvss_score": vuln.cvss_score,
                    "remediation": vuln.remediation
                }
                device_data["vulnerabilities"].append(vuln_data)

                # Count by severity
                severity = vuln.severity.lower() if vuln.severity else ""
                if severity == "critical":
                    scan_data["critical_count"] += 1
                elif severity == "high":
                    scan_data["high_count"] += 1
                elif severity == "medium":
                    scan_data["medium_count"] += 1
                elif severity == "low":
                    scan_data["low_count"] += 1

            scan_data["devices"].append(device_data)

        # Execute 6-layer reporting pipeline
        orchestrator = ReportOrchestrator()
        report_result, success = orchestrator.generate_complete_report(scan_data)

        if not success:
            return jsonify({"success": False, "error": "Report generation failed"}), 500

        # Export to all formats
        distributor = OutputDistributor(output_dir="backend/reports")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        exports = distributor.export_all_formats(
            report_result, 
            f"VAPT_Report_{scan.id}_{timestamp}"
        )

        # Save report to database
        report = Report(
            scan_id=scan.id,
            report_type="comprehensive",
            content=report_result,
            json_export=exports.get("json", {}).get("file"),
            html_export=exports.get("html", {}).get("file"),
            generated_at=datetime.utcnow()
        )
        db.session.add(report)
        db.session.commit()

        # Return report with export links and preview
        return jsonify({
            "success": True,
            "message": "Report generated successfully",
            "report_id": report.id,
            "scan_id": scan.id,
            "generated_at": report.generated_at.isoformat(),
            "formats": {
                "json": exports.get("json", {}).get("file"),
                "html": exports.get("html", {}).get("file")
            },
            "preview": {
                "executive": report_result.get("reports", {}).get("executive_summary", {}).get("sections", [])[:2],
                "risk_level": report_result.get("enriched_data", {}).get("risk_assessment", {}),
                "statistics": report_result.get("enriched_data", {}).get("statistics", {}),
                "severity_summary": report_result.get("enriched_data", {}).get("risk_summary", {}),
                "recommendations": report_result.get("enriched_data", {}).get("recommendations", [])[:3]
            },
            "enriched_data": report_result.get("enriched_data", {})
        }), 201

    except Exception as e:
        logger.error(f"Report generation error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/scan/<scan_id>/report", methods=["GET"])
def get_report(scan_id):
    """Retrieve generated report for a scan"""
    try:
        # Try parsing as integer ID first, then as string scan_id
        try:
            scan_id_int = int(scan_id)
            report = Report.query.filter_by(scan_id=scan_id_int).first()
        except (ValueError, TypeError):
            report = Report.query.filter(
                Scan.scan_id == scan_id, Report.scan_id == Scan.id
            ).first()

        if not report:
            return jsonify({"error": "Report not found"}), 404

        return jsonify({
            "id": report.id,
            "scan_id": report.scan_id,
            "report_type": report.report_type,
            "generated_at": report.generated_at.isoformat(),
            "content": report.content
        }), 200

    except Exception as e:
        logger.error(f"Report retrieval error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/<scan_id>/report/export/<format>", methods=["GET"])
def export_report(scan_id, format):
    """Download report in specific format"""
    try:
        # Try parsing as integer ID first
        try:
            scan_id_int = int(scan_id)
            report = Report.query.filter_by(scan_id=scan_id_int).first()
        except (ValueError, TypeError):
            report = Report.query.filter(
                Scan.scan_id == scan_id, Report.scan_id == Scan.id
            ).first()

        if not report:
            return jsonify({"error": "Report not found"}), 404

        if format == "json":
            file_path = report.json_export
            mimetype = "application/json"
        elif format == "html":
            file_path = report.html_export
            mimetype = "text/html"
        else:
            return jsonify({"error": "Invalid format"}), 400

        if not file_path or not os.path.exists(file_path):
            return jsonify({"error": f"{format.upper()} export not available"}), 404

        return send_file(file_path, mimetype=mimetype, as_attachment=True)

    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports", methods=["GET"])
def list_reports():
    """List all generated reports"""
    try:
        # Return sample reports with real scan data
        # In production, this would query a reports table
        scans = Scan.query.limit(5).all()
        
        reports = []
        for i, scan in enumerate(scans, 1):
            reports.append({
                "id": i,
                "scan_id": scan.scan_id,
                "type": "Technical Assessment",
                "generated_at": scan.completed_at.isoformat() if scan.completed_at else scan.started_at.isoformat()
            })
        
        return jsonify({
            "total": len(reports),
            "reports": reports
        }), 200

    except Exception as e:
        logger.error(f"Report listing error: {e}")
        return jsonify({"total": 0, "reports": []}), 200


def assess_port_risk(port_number, service_name):
    """Assess individual port risk"""
    high_risk_ports = {
        23: "CRITICAL - Telnet (unencrypted remote access)",
        21: "HIGH - FTP (unencrypted data transfer)",
        80: "MEDIUM - HTTP web interface exposed",
        554: "HIGH - RTSP stream exposed (camera feed accessible)",
        37777: "CRITICAL - Dahua DVR known vulnerabilities",
        8000: "HIGH - Hikvision DVR exposed",
        22: "MEDIUM - SSH available (requires strong credentials)",
        8080: "MEDIUM - Alternative web interface",
        443: "LOW - HTTPS web interface (encrypted)",
    }
    
    return high_risk_ports.get(port_number, "")


def calculate_device_risk(device):
    """Calculate device risk level based on open ports and vulnerabilities"""
    risk_score = 0
    
    # Count critical ports
    ports = device.ports.all()
    critical_ports = [p.port_number for p in ports if p.port_number in [23, 37777]]
    high_risk_ports = [p.port_number for p in ports if p.port_number in [21, 554, 8000, 80]]
    
    risk_score += len(critical_ports) * 3
    risk_score += len(high_risk_ports)
    
    # Count vulnerabilities
    vulns = Vulnerability.query.filter_by(device_id=device.id).all()
    critical_vulns = [v for v in vulns if v.severity and v.severity.lower() == "critical"]
    high_vulns = [v for v in vulns if v.severity and v.severity.lower() == "high"]
    
    risk_score += len(critical_vulns) * 3
    risk_score += len(high_vulns)
    
    if risk_score >= 8:
        return "CRITICAL"
    elif risk_score >= 5:
        return "HIGH"
    elif risk_score >= 3:
        return "MEDIUM"
    elif risk_score > 0:
        return "LOW"
    else:
        return "SAFE"


@app.route("/api/report/<int:report_id>", methods=["GET"])
def get_report_by_id(report_id):
    """Get report by ID"""
    try:
        report = Report.query.filter_by(id=report_id).first()
        if not report:
            return jsonify({"error": "Report not found"}), 404

        return jsonify({
            "id": report.id,
            "scan_id": report.scan_id,
            "type": report.report_type,
            "generated_at": report.generated_at.isoformat(),
            "content": report.content
        }), 200

    except Exception as e:
        logger.error(f"Report retrieval error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/<int:report_id>/download", methods=["GET"])
def download_report(report_id):
    """Download a generated report"""
    try:
        # Get the scan to generate report data
        scan = Scan.query.filter_by(id=report_id).first()
        if not scan:
            return jsonify({"error": "Report not found"}), 404
        
        # Format request from query params
        report_format = request.args.get('format', 'txt').lower()
        
        # Get scan details - ensure we're fetching actual data
        # Note: Device.scan_id contains the string scan_id value, not the integer ID
        devices = Device.query.filter_by(scan_id=scan.scan_id).all()
        
        # Get vulnerabilities for all devices in this scan
        vulnerabilities = []
        for device in devices:
            device_vulns = Vulnerability.query.filter_by(device_id=device.id).all()
            vulnerabilities.extend(device_vulns)
        
        logger.info(f"Report {report_id}: Scan={scan.scan_id}, Found {len(devices)} devices, {len(vulnerabilities)} vulnerabilities")
        
        if report_format == 'json':
            # Generate JSON report
            report_data = {
                "scan_info": {
                    "scan_id": scan.scan_id,
                    "operator": scan.operator_name,
                    "network_range": scan.network_range,
                    "status": scan.status,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                },
                "summary": {
                    "total_devices": len(devices),
                    "cctv_devices": len([d for d in devices if d.is_cctv]),
                    "total_ports": sum(d.ports.count() for d in devices),
                    "total_vulnerabilities": len(vulnerabilities),
                },
                "devices": [
                    {
                        "ip_address": d.ip_address,
                        "mac_address": d.mac_address,
                        "is_cctv": d.is_cctv,
                        "device_type": d.device_type,
                        "ports": [
                            {
                                "port_number": p.port_number,
                                "service_name": p.service_name,
                                "service_version": p.service_version,
                                "state": p.state
                            }
                            for p in d.ports
                        ]
                    }
                    for d in devices
                ],
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "title": v.title,
                        "severity": v.severity,
                        "description": v.description,
                        "remediation": v.remediation,
                    }
                    for v in vulnerabilities
                ]
            }
            
            import json
            from io import BytesIO
            json_str = json.dumps(report_data, indent=2, default=str)
            
            return send_file(
                BytesIO(json_str.encode('utf-8')),
                mimetype='application/json',
                as_attachment=True,
                download_name=f"VAPT_Report_{scan.scan_id}.json"
            )
        
        elif report_format == 'txt':
            # Generate Text report focused on vulnerabilities
            from io import BytesIO
            
            text_lines = []
            text_lines.append("=" * 100)
            text_lines.append("CCTV VULNERABILITY ASSESSMENT & PENETRATION TEST (VAPT) REPORT")
            text_lines.append("=" * 100)
            text_lines.append("")
            
            # Scan summary
            text_lines.append("SCAN INFORMATION")
            text_lines.append("-" * 100)
            text_lines.append(f"Scan ID:          {scan.scan_id}")
            text_lines.append(f"Operator:         {scan.operator_name}")
            text_lines.append(f"Network Range:    {scan.network_range}")
            text_lines.append(f"Status:           {scan.status.upper()}")
            text_lines.append(f"Started:          {scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'}")
            text_lines.append(f"Completed:        {scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else 'N/A'}")
            text_lines.append("")
            
            # Executive summary
            text_lines.append("EXECUTIVE SUMMARY")
            text_lines.append("-" * 100)
            text_lines.append(f"Total Devices Discovered:      {len(devices)}")
            text_lines.append(f"CCTV Devices Found:            {len([d for d in devices if d.is_cctv])}")
            text_lines.append(f"Total Open Ports:              {sum(d.ports.count() for d in devices)}")
            text_lines.append(f"Total Vulnerabilities Found:   {len(vulnerabilities)}")
            text_lines.append("")
            
            # Vulnerability severity breakdown
            critical = [v for v in vulnerabilities if v.severity == 'critical']
            high = [v for v in vulnerabilities if v.severity == 'high']
            medium = [v for v in vulnerabilities if v.severity == 'medium']
            low = [v for v in vulnerabilities if v.severity == 'low']
            
            text_lines.append("VULNERABILITY SEVERITY BREAKDOWN")
            text_lines.append("-" * 100)
            text_lines.append(f"CRITICAL:    {len(critical)} vulnerabilities")
            text_lines.append(f"HIGH:        {len(high)} vulnerabilities")
            text_lines.append(f"MEDIUM:      {len(medium)} vulnerabilities")
            text_lines.append(f"LOW:         {len(low)} vulnerabilities")
            text_lines.append("")
            text_lines.append("")
            
            # Detailed vulnerability analysis
            text_lines.append("DETAILED VULNERABILITY ANALYSIS")
            text_lines.append("=" * 100)
            text_lines.append("")
            
            if vulnerabilities:
                for idx, v in enumerate(vulnerabilities, 1):
                    device = Device.query.get(v.device_id)
                    text_lines.append(f"VULNERABILITY #{idx}")
                    text_lines.append("-" * 100)
                    text_lines.append(f"CVE ID:              {v.cve_id or 'N/A'}")
                    text_lines.append(f"Title:               {v.title}")
                    text_lines.append(f"Severity:            {v.severity.upper() if v.severity else 'UNKNOWN'}")
                    text_lines.append(f"CVSS Score:          {v.cvss_score if v.cvss_score else 'N/A'}")
                    text_lines.append(f"CWE ID:              {v.cwe_id or 'N/A'}")
                    text_lines.append(f"Affected Device:     {device.ip_address if device else 'Unknown'}")
                    text_lines.append(f"Affected Component:  {v.affected_component or 'N/A'}")
                    text_lines.append(f"Discovered At:       {v.discovered_at.strftime('%Y-%m-%d %H:%M:%S') if v.discovered_at else 'N/A'}")
                    text_lines.append(f"Verified:            {'Yes' if v.verified else 'No'}")
                    text_lines.append("")
                    
                    if v.description:
                        text_lines.append("DESCRIPTION:")
                        text_lines.append(v.description)
                        text_lines.append("")
                    
                    if v.remediation:
                        text_lines.append("REMEDIATION:")
                        text_lines.append(v.remediation)
                        text_lines.append("")
                    
                    if v.proof_of_concept:
                        text_lines.append("PROOF OF CONCEPT:")
                        text_lines.append(v.proof_of_concept)
                        text_lines.append("")
                    
                    text_lines.append("")
            else:
                text_lines.append("No vulnerabilities found during this scan.")
                text_lines.append("")
            
            # Devices discovered
            text_lines.append("")
            text_lines.append("DISCOVERED DEVICES")
            text_lines.append("=" * 100)
            text_lines.append("")
            
            if devices:
                for idx, device in enumerate(devices, 1):
                    text_lines.append(f"DEVICE #{idx}")
                    text_lines.append("-" * 100)
                    text_lines.append(f"IP Address:        {device.ip_address}")
                    text_lines.append(f"MAC Address:       {device.mac_address or 'N/A'}")
                    text_lines.append(f"Hostname:          {device.hostname or 'N/A'}")
                    text_lines.append(f"Manufacturer:      {device.manufacturer or 'N/A'}")
                    text_lines.append(f"Model:             {device.model or 'N/A'}")
                    text_lines.append(f"Device Type:       {device.device_type or 'Unknown'}")
                    text_lines.append(f"Is CCTV:           {'Yes' if device.is_cctv else 'No'}")
                    text_lines.append(f"Firmware Version:  {device.firmware_version or 'N/A'}")
                    text_lines.append(f"Confidence Score:  {device.confidence_score or 'N/A'}")
                    text_lines.append(f"Open Ports:        {device.ports.count()}")
                    text_lines.append("")
                    
                    if device.ports:
                        text_lines.append("  OPEN PORTS & SERVICES:")
                        for port in device.ports:
                            service_info = f"{port.service_name or 'Unknown'} ({port.state})"
                            text_lines.append(f"    Port {port.port_number}/{port.protocol}: {service_info}")
                            if port.banner:
                                banner_lines = port.banner.split('\n')[:3]  # Limit to first 3 lines
                                for banner_line in banner_lines:
                                    text_lines.append(f"      Banner: {banner_line[:80]}")
                            
                            # Port risk assessment
                            port_risks = assess_port_risk(port.port_number, port.service_name)
                            if port_risks:
                                text_lines.append(f"      Risk: {port_risks}")
                        text_lines.append("")
                    
                    # Device risk level based on ports
                    device_risk = calculate_device_risk(device)
                    if device_risk:
                        text_lines.append(f"  Device Risk Level: {device_risk}")
                        text_lines.append("")
                    
                    text_lines.append("")
            
            # Footer
            text_lines.append("")
            text_lines.append("=" * 100)
            text_lines.append(f"Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
            text_lines.append("CCTV VAPT Platform")
            text_lines.append("=" * 100)
            
            text_content = '\n'.join(text_lines)
            
            return send_file(
                BytesIO(text_content.encode('utf-8')),
                mimetype='text/plain',
                as_attachment=True,
                download_name=f"VAPT_Report_{scan.scan_id}.txt"
            )
        
        elif report_format == 'pdf':
            # Generate PDF report using reportlab
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.lib.units import inch
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
                from reportlab.lib import colors
                from reportlab.lib.enums import TA_CENTER
                from io import BytesIO
                
                # Create PDF buffer
                pdf_buffer = BytesIO()
                doc = SimpleDocTemplate(pdf_buffer, pagesize=letter,
                                        topMargin=0.5*inch, bottomMargin=0.5*inch,
                                        leftMargin=0.75*inch, rightMargin=0.75*inch)
                
                # Container for PDF elements
                elements = []
                
                # Styles
                styles = getSampleStyleSheet()
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=24,
                    textColor=colors.HexColor('#0a1f3e'),
                    spaceAfter=30,
                    alignment=TA_CENTER
                )
                heading_style = ParagraphStyle(
                    'CustomHeading',
                    parent=styles['Heading2'],
                    fontSize=14,
                    textColor=colors.HexColor('#0066ff'),
                    spaceAfter=12,
                    spaceBefore=12
                )
                
                # Title
                elements.append(Paragraph("CCTV VULNERABILITY ASSESSMENT & PENETRATION TEST REPORT", title_style))
                elements.append(Spacer(1, 0.3*inch))
                
                # Scan Information Section
                elements.append(Paragraph("SCAN INFORMATION", heading_style))
                scan_info_data = [
                    ["Scan ID:", scan.scan_id],
                    ["Operator:", scan.operator_name],
                    ["Network Range:", scan.network_range or 'N/A'],
                    ["Status:", scan.status.upper()],
                    ["Started:", scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'],
                    ["Completed:", scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else 'N/A'],
                ]
                scan_table = Table(scan_info_data, colWidths=[2*inch, 4*inch])
                scan_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f8ff')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ]))
                elements.append(scan_table)
                elements.append(Spacer(1, 0.3*inch))
                
                # Executive Summary
                elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
                summary_data = [
                    ["Metric", "Count"],
                    ["Total Devices", str(len(devices))],
                    ["CCTV Devices", str(len([d for d in devices if d.is_cctv]))],
                    ["Total Open Ports", str(sum(d.ports.count() for d in devices))],
                    ["Total Vulnerabilities", str(len(vulnerabilities))],
                ]
                summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0a1f3e')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
                ]))
                elements.append(summary_table)
                elements.append(Spacer(1, 0.3*inch))
                
                # Vulnerability Severity Breakdown
                critical = [v for v in vulnerabilities if v.severity and v.severity.lower() == 'critical']
                high = [v for v in vulnerabilities if v.severity and v.severity.lower() == 'high']
                medium = [v for v in vulnerabilities if v.severity and v.severity.lower() == 'medium']
                low = [v for v in vulnerabilities if v.severity and v.severity.lower() == 'low']
                
                elements.append(Paragraph("VULNERABILITY SEVERITY BREAKDOWN", heading_style))
                severity_data = [
                    ["Severity", "Count"],
                    ["CRITICAL", str(len(critical))],
                    ["HIGH", str(len(high))],
                    ["MEDIUM", str(len(medium))],
                    ["LOW", str(len(low))],
                ]
                severity_table = Table(severity_data, colWidths=[3*inch, 2*inch])
                severity_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0a1f3e')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
                ]))
                elements.append(severity_table)
                elements.append(PageBreak())
                
                # Detailed Vulnerabilities
                if vulnerabilities:
                    elements.append(Paragraph("DETAILED VULNERABILITY ANALYSIS", heading_style))
                    elements.append(Spacer(1, 0.2*inch))
                    
                    for idx, v in enumerate(vulnerabilities, 1):
                        device = Device.query.get(v.device_id)
                        vuln_title = f"Vulnerability #{idx}: {v.title[:50]}"
                        elements.append(Paragraph(vuln_title, ParagraphStyle(
                            'VulnTitle',
                            parent=styles['Normal'],
                            fontSize=11,
                            textColor=colors.HexColor('#c62828'),
                            spaceAfter=6
                        )))
                        
                        vuln_data = [
                            ["CVE ID:", v.cve_id or "N/A"],
                            ["Severity:", (v.severity.upper() if v.severity else "UNKNOWN")],
                            ["CVSS Score:", str(v.cvss_score) if v.cvss_score else "N/A"],
                            ["CWE ID:", v.cwe_id or "N/A"],
                            ["Affected Device:", device.ip_address if device else "Unknown"],
                            ["Component:", v.affected_component or "N/A"],
                            ["Discovery Date:", v.discovered_at.strftime('%Y-%m-%d %H:%M:%S') if v.discovered_at else 'N/A'],
                        ]
                        vuln_table = Table(vuln_data, colWidths=[1.5*inch, 4.5*inch])
                        vuln_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f8ff')),
                            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                            ('TOPPADDING', (0, 0), (-1, -1), 6),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ]))
                        elements.append(vuln_table)
                        elements.append(Spacer(1, 0.1*inch))
                        
                        if v.description:
                            elements.append(Paragraph("<b>Description:</b>", styles['Normal']))
                            desc_text = v.description[:300] + "..." if len(v.description or "") > 300 else v.description
                            elements.append(Paragraph(desc_text, styles['Normal']))
                            elements.append(Spacer(1, 0.05*inch))
                        
                        if v.remediation:
                            elements.append(Paragraph("<b>Remediation:</b>", styles['Normal']))
                            rem_text = v.remediation[:300] + "..." if len(v.remediation or "") > 300 else v.remediation
                            elements.append(Paragraph(rem_text, styles['Normal']))
                            elements.append(Spacer(1, 0.1*inch))
                
                # Build PDF
                doc.build(elements)
                pdf_buffer.seek(0)
                
                return send_file(
                    pdf_buffer,
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name=f"VAPT_Report_{scan.scan_id}.pdf"
                )
                
            except ImportError:
                logger.error("reportlab not installed. Please install: pip install reportlab")
                return jsonify({"error": "PDF generation not available. Install reportlab: pip install reportlab"}), 500
        
        elif report_format == 'html':
            # Generate HTML report
            vuln_rows = ''.join([
                f"""<tr>
                    <td>{v.cve_id}</td>
                    <td>{v.title}</td>
                    <td><span class="severity-{v.severity.lower()}">{v.severity.upper()}</span></td>
                    <td>{(v.remediation[:50] + '...') if v.remediation and len(v.remediation) > 50 else (v.remediation or 'N/A')}</td>
                </tr>"""
                for v in vulnerabilities
            ])
            
            device_rows = ''.join([
                f"""<tr>
                    <td>{d.ip_address}</td>
                    <td>{d.mac_address or 'N/A'}</td>
                    <td>{'CCTV' if d.is_cctv else (d.device_type or 'Unknown')}</td>
                    <td>{d.ports.count()}</td>
                </tr>"""
                for d in devices
            ])
            
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>VAPT Report - {scan.scan_id}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #0a1f3e;
            border-bottom: 3px solid #00d4ff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #0066ff;
            margin-top: 30px;
        }}
        .scan-info {{
            background: #f0f8ff;
            padding: 15px;
            border-left: 4px solid #0066ff;
            margin: 20px 0;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #f9f9f9;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #e0e0e0;
        }}
        .stat-card strong {{
            color: #0066ff;
            display: block;
            font-size: 24px;
        }}
        .stat-card span {{
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background: #0a1f3e;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .severity-critical {{
            background: #ffebee;
            color: #c62828;
            padding: 4px 8px;
            border-radius: 3px;
        }}
        .severity-high {{
            background: #fff3e0;
            color: #e65100;
            padding: 4px 8px;
            border-radius: 3px;
        }}
        .severity-medium {{
            background: #e8f5e9;
            color: #2e7d32;
            padding: 4px 8px;
            border-radius: 3px;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #999;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>CCTV VAPT Report</h1>
        
        <div class="scan-info">
            <p><strong>Scan ID:</strong> {scan.scan_id}</p>
            <p><strong>Operator:</strong> {scan.operator_name}</p>
            <p><strong>Network Range:</strong> {scan.network_range}</p>
            <p><strong>Status:</strong> {scan.status.upper()}</p>
            <p><strong>Started:</strong> {scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'}</p>
            <p><strong>Completed:</strong> {scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else 'N/A'}</p>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="stat-card">
                <strong>{len(devices)}</strong>
                <span>Total Devices</span>
            </div>
            <div class="stat-card">
                <strong>{len([d for d in devices if d.is_cctv])}</strong>
                <span>CCTV Devices</span>
            </div>
            <div class="stat-card">
                <strong>{sum(d.ports.count() for d in devices)}</strong>
                <span>Open Ports</span>
            </div>
            <div class="stat-card">
                <strong>{len(vulnerabilities)}</strong>
                <span>Vulnerabilities</span>
            </div>
        </div>
        
        <h2>Discovered Devices</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Type</th>
                    <th>Open Ports</th>
                </tr>
            </thead>
            <tbody>
                {device_rows}
            </tbody>
        </table>
        
        <h2>Vulnerabilities Found</h2>
        <table>
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows}
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by CCTV VAPT Platform | Report Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </div>
</body>
</html>"""
            
            from io import BytesIO
            html_bytes = html_content.encode('utf-8')
            
            return send_file(
                BytesIO(html_bytes),
                mimetype='text/html',
                as_attachment=True,
                download_name=f"VAPT_Report_{scan.scan_id}.html"
            )
        
        else:
            return jsonify({"error": "Invalid format. Use 'txt', 'json', 'html', or 'pdf'"}), 400
            
    except Exception as e:
        logger.error(f"Report download error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/scans", methods=["GET"])
def list_scans():
    """List all scans"""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    scans = Scan.query.order_by(Scan.started_at.desc()).paginate(
        page=page, per_page=per_page
    )

    return jsonify(
        {
            "success": True,
            "data": {
                "scans": [scan.to_dict() for scan in scans.items],
                "total": scans.total,
                "pages": scans.pages,
                "current_page": page,
            },
        }
    )


@app.route("/api/audit-logs", methods=["GET"])
def list_audit_logs():
    """List audit logs"""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page
    )

    return jsonify(
        {
            "success": True,
            "data": {
                "logs": [log.to_dict() for log in logs.items],
                "total": logs.total,
                "pages": logs.pages,
                "current_page": page,
            },
        }
    )


@app.route("/api/analytics/summary", methods=["GET"])
def get_analytics_summary():
    """Get analytics summary"""
    total_scans = Scan.query.count()
    completed_scans = Scan.query.filter_by(status="completed").count()
    total_devices = Device.query.filter_by(is_cctv=True).count()
    total_vulns = Vulnerability.query.count()

    critical_vulns = Vulnerability.query.filter_by(severity="critical").count()
    high_vulns = Vulnerability.query.filter_by(severity="high").count()

    return jsonify(
        {
            "success": True,
            "data": {
                "total_scans": total_scans,
                "completed_scans": completed_scans,
                "total_cctv_devices": total_devices,
                "total_vulnerabilities": total_vulns,
                "critical_vulnerabilities": critical_vulns,
                "high_vulnerabilities": high_vulns,
            },
        }
    )


# =============================================================================
# WebSocket Events
# =============================================================================


@socketio.on("connect")
def handle_connect():
    """Handle WebSocket connection"""
    logger.info(f"Client connected: {request.sid}")
    emit("connected", {"status": "connected"})


@socketio.on("disconnect")
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.info(f"Client disconnected: {request.sid}")


@socketio.on("subscribe_scan")
def handle_subscribe_scan(data):
    """Subscribe to scan updates"""
    scan_id = data.get("scan_id")
    logger.info(f"Client {request.sid} subscribed to scan {scan_id}")


# =============================================================================
# Register Reports API Blueprint
# =============================================================================

try:
    from backend.api.reports import register_reports_blueprint
    register_reports_blueprint(app)
    logger.info("Reports API blueprint registered successfully")
except ImportError as e:
    logger.warning(f"Could not load Reports API blueprint: {e}. Report generation endpoints may not be available.")
except Exception as e:
    logger.warning(f"Error registering Reports API blueprint: {e}")


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    # Force non-debug execution for stable background runs
    app.debug = False
    socketio.run(app, host="0.0.0.0", port=5000)
