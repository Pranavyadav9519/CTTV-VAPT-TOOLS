CREATE TABLE scans (
	id INTEGER NOT NULL,
	scan_id VARCHAR(50) NOT NULL,
	operator_name VARCHAR(100) NOT NULL,
	status VARCHAR(20),
	scan_type VARCHAR(50),
	network_range VARCHAR(50),
	started_at DATETIME,
	completed_at DATETIME,
	total_hosts_found INTEGER,
	cctv_devices_found INTEGER,
	vulnerabilities_found INTEGER,
	critical_count INTEGER,
	high_count INTEGER,
	medium_count INTEGER,
	low_count INTEGER,
	error_message TEXT,
	PRIMARY KEY (id)
)

CREATE TABLE devices (
	id INTEGER NOT NULL,
	scan_id INTEGER NOT NULL,
	ip_address VARCHAR(45) NOT NULL,
	mac_address VARCHAR(17),
	hostname VARCHAR(255),
	manufacturer VARCHAR(100),
	device_type VARCHAR(50),
	model VARCHAR(100),
	firmware_version VARCHAR(50),
	is_cctv BOOLEAN,
	confidence_score FLOAT,
	discovered_at DATETIME,
	last_seen DATETIME,
	PRIMARY KEY (id),
	FOREIGN KEY(scan_id) REFERENCES scans (id)
)

CREATE TABLE audit_logs (
	id INTEGER NOT NULL,
	scan_id INTEGER,
	timestamp DATETIME,
	operator VARCHAR(100) NOT NULL,
	action VARCHAR(100) NOT NULL,
	target VARCHAR(255),
	details TEXT,
	ip_address VARCHAR(45),
	user_agent VARCHAR(500),
	status VARCHAR(20),
	error_message TEXT,
	PRIMARY KEY (id),
	FOREIGN KEY(scan_id) REFERENCES scans (id)
)

CREATE TABLE reports (
	id INTEGER NOT NULL,
	report_id VARCHAR(50) NOT NULL,
	scan_id INTEGER NOT NULL,
	title VARCHAR(255),
	format VARCHAR(10),
	file_path VARCHAR(500),
	file_size INTEGER,
	generated_at DATETIME,
	generated_by VARCHAR(100),
	checksum VARCHAR(64),
	PRIMARY KEY (id),
	UNIQUE (report_id),
	FOREIGN KEY(scan_id) REFERENCES scans (id)
)

CREATE TABLE ports (
	id INTEGER NOT NULL,
	device_id INTEGER NOT NULL,
	port_number INTEGER NOT NULL,
	protocol VARCHAR(10),
	state VARCHAR(20),
	service_name VARCHAR(50),
	service_version VARCHAR(100),
	banner TEXT,
	scanned_at DATETIME,
	PRIMARY KEY (id),
	FOREIGN KEY(device_id) REFERENCES devices (id)
)

CREATE TABLE vulnerabilities (
	id INTEGER NOT NULL,
	device_id INTEGER NOT NULL,
	vuln_id VARCHAR(50),
	title VARCHAR(255) NOT NULL,
	description TEXT,
	severity VARCHAR(20),
	cvss_score FLOAT,
	cve_id VARCHAR(20),
	cwe_id VARCHAR(20),
	affected_component VARCHAR(100),
	remediation TEXT,
	"references" TEXT,
	proof_of_concept TEXT,
	discovered_at DATETIME,
	verified BOOLEAN,
	false_positive BOOLEAN,
	PRIMARY KEY (id),
	FOREIGN KEY(device_id) REFERENCES devices (id)
)