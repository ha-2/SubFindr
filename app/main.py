"""
SubFindr - Open Source Subdomain Enumeration Tool
Author: ha-2
GitHub: https://github.com/ha-2
License: CC BY-NC 4.0
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from typing import List, Dict, Any
from datetime import datetime
import asyncio
import logging
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

from app.schemas import ScanRequest, ScanResponse
from app.services.subdomain_enum import scan_domain

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SubFindr API",
    description="Subdomain enumeration tool",
    version="1.0.0"
)

# Mount static files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
static_dir = os.path.join(BASE_DIR, "static")
INDEX_PATH = os.path.join(BASE_DIR, "static", "index.html")

@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(INDEX_PATH)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.post("/scan", response_model=ScanResponse)
async def scan_subdomains(request: ScanRequest):
    """Scan subdomains for a given domain"""
    try:
        # Record start time
        started_at = datetime.now()
        
        # Perform the scan
        subdomains = await scan_domain(request.domain, mode=request.mode)
        
        # Compute counts
        total_subdomains = len(subdomains)
        alive_count = sum(1 for s in subdomains if s.get("is_alive", False))
        dead_count = total_subdomains - alive_count
        
        # Record end time
        finished_at = datetime.now()
        
        # Return the response
        return ScanResponse(
            domain=request.domain,
            started_at=started_at,
            finished_at=finished_at,
            subdomains=subdomains,
            total_subdomains=total_subdomains,
            alive_count=alive_count,
            dead_count=dead_count
        )
    except Exception as e:
        logger.error(f"Scan failed for domain {request.domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)