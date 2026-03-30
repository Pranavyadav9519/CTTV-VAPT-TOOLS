"""
Fingerprinting Package
Enhanced device fingerprinting: firmware extraction, version matching against
known-vulnerable firmware versions.
"""

from .firmware_extractor import FirmwareExtractor

__all__ = ["FirmwareExtractor"]
