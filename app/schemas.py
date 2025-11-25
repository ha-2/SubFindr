"""
SubFindr - Open Source Subdomain Enumeration Tool
Author: ha-2
GitHub: https://github.com/ha-2
License: CC BY-NC 4.0
"""

from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class ScanRequest(BaseModel):
    domain: str
    mode: str = "basic"

class SubdomainInfo(BaseModel):
    host: str
    ip: Optional[str]
    is_alive: bool
    http_status: Optional[int]
    sources: List[str]

class ScanResponse(BaseModel):
    domain: str
    started_at: datetime
    finished_at: datetime
    subdomains: List[SubdomainInfo]
    total_subdomains: int
    alive_count: int
    dead_count: int