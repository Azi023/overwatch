# src/overwatch_core/api/schemas.py

from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime

# --- Target Schemas ---
class TargetCreate(BaseModel):
    ip_or_domain: str
    description: Optional[str] = None

class TargetResponse(TargetCreate):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# --- Scan Schemas ---
class ScanCreate(BaseModel):
    target_id: int
    tool: str = "web_scanner" # nmap, web_scanner
    profile: str = "balanced" # stealth, balanced, aggressive, custom_mix

class ScanResponse(BaseModel):
    id: int
    target_id: int
    tool_name: str
    status: str
    scan_type: Optional[str]
    started_at: datetime
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True

# --- Finding Schemas ---
class FindingResponse(BaseModel):
    id: int
    title: str
    severity: str
    description: Optional[str]
    evidence: Optional[str]
    
    class Config:
        from_attributes = True
