"""
Pydantic request schemas for API input validation across all endpoints
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List
import ipaddress


class ScanCreateSchema(BaseModel):
    """Schema for creating a new scan"""
    network_range: str = Field(..., description="CIDR notation network range (e.g., 192.168.1.0/24)")
    scan_name: Optional[str] = Field(None, max_length=255)
    scan_type: Optional[str] = Field("network", regex="^(network|external|internal)$")
    ports: Optional[List[int]] = Field(None, description="Specific ports to scan")
    timeout: Optional[int] = Field(300, ge=30, le=3600, description="Scan timeout in seconds")
    max_threads: Optional[int] = Field(4, ge=1, le=50)
    description: Optional[str] = Field(None, max_length=1000)
    
    @validator('network_range')
    def validate_network_range(cls, v):
        """Validate CIDR notation"""
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError("Invalid CIDR notation")
        return v
    
    @validator('ports')
    def validate_ports(cls, v):
        """Validate port numbers"""
        if v:
            for port in v:
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port {port} out of range (1-65535)")
        return v


class ReportGenerateSchema(BaseModel):
    """Schema for generating a report"""
    scan_id: str = Field(..., description="Scan ID to generate report for")
    format: str = Field("html", regex="^(html|json|pdf)$")
    title: Optional[str] = Field(None, max_length=500)
    include_recommendations: Optional[bool] = True
    include_conclusions: Optional[bool] = True


class DeviceFilterSchema(BaseModel):
    """Schema for device filtering"""
    scan_id: Optional[str] = None
    is_cctv: Optional[bool] = None
    ip_address: Optional[str] = None
    page: int = Field(1, ge=1)
    limit: int = Field(20, ge=1, le=100)


class VulnerabilityFilterSchema(BaseModel):
    """Schema for vulnerability filtering"""
    scan_id: Optional[str] = None
    device_id: Optional[str] = None
    severity: Optional[str] = Field(None, regex="^(critical|high|medium|low|info)$")
    page: int = Field(1, ge=1)
    limit: int = Field(20, ge=1, le=100)


class AuthLoginSchema(BaseModel):
    """Schema for user login"""
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=6)
    tenant_id: str = Field(...)


class ReportCompareSchema(BaseModel):
    """Schema for comparing two reports"""
    report_id_1: str = Field(...)
    report_id_2: str = Field(...)
