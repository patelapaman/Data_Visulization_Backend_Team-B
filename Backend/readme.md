# AI-Assisted Threat Detection Dashboard — Backend

Flask + MongoDB backend that powers the SOC dashboard: data
processing/enrichment (Milestone 1) and the AI Threat Detection engine
(Milestone 2 — Isolation Forest anomaly detection + hybrid security rules).

This repo is the **backend half** of a two-repo project. The frontend
(separate repo) talks to this API over REST.

---

## Requirements

- Python 3.10+
- **MongoDB running and reachable** — the app requires this to start
  (`REQUIRE_MONGODB=True` by default; see below).
  - Local: install MongoDB Community Server and run `mongod`, or run it via
    Docker: `docker run -d -p 27017:27017 --name threat-mongo mongo:7`
  - Cloud: a MongoDB Atlas connection string works too.

## Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` if your MongoDB isn't on the default local port:

```
MONGO_URI=mongodb://127.0.0.1:27017/
DATABASE_NAME=ThreatDetectionDB
CORS_ORIGINS=http://localhost:5173      # your frontend's dev URL
```

## Run

```bash
python app.py
```

The API starts on `http://127.0.0.1:5000` by default. On first run with
`AUTO_SEED_MONGODB=True`, it seeds the database from the bundled processed
dataset in `data/`.

## Run the tests

```bash
pytest
```

---

## Environment variables (`.env`)

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask session/JWT signing key — change in production |
| `MONGO_URI` | MongoDB connection string |
| `DATABASE_NAME` / `MONGO_DB` | Database name |
| `REQUIRE_MONGODB` | If `True`, the app refuses to start without a reachable MongoDB. Set `False` only for quick local UI checks — most routes still won't have data. |
| `AUTO_SEED_MONGODB` | Seed the DB from `data/` on first run |
| `MODEL_VERSION` | Tag stored alongside predictions, e.g. `IF_SHARED_V2` |
| `CORS_ORIGINS` | Comma-separated list of allowed frontend origins |

---

## API reference

### Milestone 1 — dashboard data
```
GET  /api/dashboard
GET  /api/events
GET  /api/assets
GET  /api/threats
GET  /api/incidents
GET  /api/vulnerabilities
GET  /api/analytics
GET  /api/profile
PUT  /api/profile
GET  /api/notifications
POST /api/auth/login
POST /api/auth/register
```

### Milestone 2 — AI threat detection (`/api/milestone2`)
```
GET  /api/milestone2/health              Engine status + dataset size
POST /api/milestone2/predict             Score a single security event
GET  /api/milestone2/predictions         List stored predictions (paginated)
GET  /api/milestone2/predictions/{id}    One prediction + full event details
GET  /api/milestone2/anomalies           Anomalies only
GET  /api/milestone2/model-performance   Precision/recall/F1 if labels exist
GET  /api/milestone2/threat-summary      KPI totals + distribution
```

Example `POST /api/milestone2/predict` body:
```json
{
  "event_id": "EVT99999",
  "event_type": "Brute Force",
  "failed_login_attempts": 18,
  "cvss_score": 8.9
}
```
> Note: `event_id` is required by the schema (used as the MongoDB key for
> the stored prediction), even though some earlier docs' examples omit it.

---

## ML pipeline (Milestone 2)

- **Layer 1 — Anomaly detection**: Isolation Forest (300 estimators),
  trained on the 18-feature matrix described in
  `docs/milestone2/feature_selection.md`.
- **Layer 2 — Hybrid rules**: brute-force (>10 failed logins), malware
  detected, critical CVE (≥9.0), impossible travel, and multi-indicator
  escalation — layered on top of the anomaly score for an explainable
  confidence score and severity classification.
- **Model evaluation**: `GET /model-performance` reports real
  precision/recall/F1 only when reliable labels exist in the dataset —
  it explicitly reports "unavailable" rather than fabricating metrics.
- Trained model + metadata are versioned in `models/`
  (`isolation_forest_pipeline.pkl`, `model_metadata.json`) and
  auto-retrain if the dataset fingerprint or scikit-learn version changes.

See `docs/milestone2/` for the full write-ups (feature selection, ML
preprocessing, model evaluation, API testing, checklist).

---

## Project structure

```
backend/
├─ app.py                    App factory / entry point
├─ config.py
├─ routes/                   Flask blueprints (auth, dashboard, etc.)
├─ database/                 MongoDB connection + repositories
├─ milestone2_engine/
│  ├─ ml/                    preprocessing.py, anomaly_detection.py, feature_config.py
│  ├─ services/              scoring_service.py, prediction_service.py
│  ├─ database/repository.py threat_predictions collection
│  └─ routes.py              /api/milestone2/* blueprint
├─ models/                   Saved model + metadata
├─ data/                     Bundled processed dataset used to seed MongoDB
├─ tests/                    pytest suite
└─ docs/milestone2/          Feature selection, evaluation, API testing docs
```
