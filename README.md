# API Sentinel

**CyberCup 6.0 Challenge:** CC6-IC07: API Discovery, Security and Abuse Prevention

## Objective

API Sentinel is a security monitoring and discovery platform that identifies, analyzes, and protects APIs from shadow APIs, abuse patterns, and security risks. The system captures API traffic, detects anomalies, discovers undocumented endpoints, and provides risk scoring and alerting.

## Technology Stack

- **Backend:** Python, FastAPI, Pydantic, Uvicorn
- **Database:** SQLite, JSONL
- **Testing:** HTTPX
- **Frontend:** (To be implemented)

## Project Structure

- `backend/` — FastAPI application, discovery, security detection, and storage
- `frontend/` — Web interface (planned)
- `docs/` — Documentation and architecture
- `backend/simulator/` — Traffic simulation and testing tools

## Running the Backend

```bash
cd backend
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Next Steps

1. Implement core modules (capture, discovery, abuse detection)
2. Set up API routes for inventory and alerts
3. Configure SQLite storage layer
4. Build risk scoring engine
5. Develop frontend dashboard
