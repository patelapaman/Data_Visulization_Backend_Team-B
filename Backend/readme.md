<<<<<<< HEAD
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
=======
# AI-Assisted Threat Detection Dashboard — Backend

## 📌 Project Overview

The **AI-Assisted Threat Detection Dashboard** is a backend system designed to collect, clean, enrich, analyze, and classify cybersecurity data.

The system combines:

* Data processing
* Threat intelligence
* Vulnerability information
* MITRE ATT&CK mapping
* Machine Learning
* Anomaly detection
* Risk scoring
* Incident management
* Security analytics
* MongoDB database storage
* REST APIs
* Dashboard analytics
* CSV export
* PDF report generation

The backend provides APIs that can be consumed by a frontend dashboard to visualize security events, threats, incidents, risk levels, attack patterns, and targeted assets.

---

# 🎯 Objectives

The main objectives of the backend are:

1. Collect cybersecurity datasets.
2. Clean and standardize raw data.
3. Enrich security events using vulnerabilities and threat intelligence.
4. Map threats to MITRE ATT&CK techniques.
5. Perform feature engineering.
6. Detect anomalous security activity.
7. Predict whether activity is suspicious or malicious.
8. Calculate threat and risk scores.
9. Assign risk levels.
10. Generate explanations for predictions.
11. Create and manage security incidents.
12. Store processed data in MongoDB.
13. Provide REST APIs for the frontend.
14. Generate dashboard analytics.
15. Provide threat timelines and attack heatmaps.
16. Identify top targeted assets.
17. Export security data as CSV.
18. Generate security reports as PDF.

---

# 🏗️ System Architecture

```text
                    ┌───────────────────────┐
                    │     Data Sources      │
                    │                       │
                    │ Kaggle / CSV / Logs   │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Data Collection     │
                    │   data_collection/    │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │    Data Cleaning      │
                    │  preprocessing/       │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Threat Enrichment     │
                    │ Vulnerabilities +     │
                    │ Threat Intelligence   │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   MITRE ATT&CK        │
                    │       Mapping         │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Feature Engineering   │
                    └───────────┬───────────┘
                                │
                                ▼
              ┌─────────────────┴─────────────────┐
              │                                   │
              ▼                                   ▼
    ┌───────────────────┐              ┌───────────────────┐
    │ Anomaly Detection │              │ ML Classification │
    │ Isolation Forest  │              │ Threat Prediction │
    └─────────┬─────────┘              └─────────┬─────────┘
              │                                  │
              └────────────────┬─────────────────┘
                               ▼
                    ┌───────────────────────┐
                    │    Risk Scoring       │
                    │ Risk Level + Priority │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Incident Management   │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │       MongoDB         │
                    │     Database Layer    │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │      Flask APIs       │
                    │       routes/         │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Frontend Dashboard  │
                    └───────────────────────┘
```

---

# 📂 Project Structure

```text
Backend/
│
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── .env
├── .gitignore
│
├── data_collection/
│   ├── __init__.py
│   └── data_collection.py
│
├── preprocessing/
│   ├── __init__.py
│   ├── data_cleaning.py
│   └── feature_engineering.py
│
├── database/
│   ├── __init__.py
│   ├── mongodb.py
│   ├── insert_data.py
│   ├── queries.py
│   ├── prediction_repository.py
│   └── incident_repository.py
│
├── models/
│   ├── __init__.py
│   ├── asset_model.py
│   ├── vulnerability_model.py
│   ├── threat_model.py
│   ├── security_event_model.py
│   ├── incident_model.py
│   ├── mitre_model.py
│   └── prediction_model.py
│
├── services/
│   ├── __init__.py
│   ├── pipeline_service.py
│   ├── enrichment_service.py
│   ├── mitre_service.py
│   ├── analytics_service.py
│   ├── feature_service.py
│   ├── prediction_service.py
│   ├── scoring_service.py
│   ├── risk_service.py
│   ├── incident_service.py
│   └── intelligence_service.py
│
├── routes/
│   ├── __init__.py
│   ├── assets.py
│   ├── vulnerabilities.py
│   ├── threats.py
│   ├── incidents.py
│   ├── analytics.py
│   ├── dashboard.py
│   ├── export.py
│   ├── prediction_routes.py
│   ├── anomaly_routes.py
│   ├── risk_routes.py
│   ├── incident_routes.py
│   └── intelligence_routes.py
│
├── ml/
│   ├── __init__.py
│   ├── preprocessing.py
│   ├── feature_selection.py
│   ├── anomaly_detection.py
│   ├── classifier.py
│   ├── scoring.py
│   ├── rules.py
│   ├── explainability.py
│   ├── evaluation.py
│   └── model_loader.py
│
├── trained_models/
│   ├── isolation_forest_v1.pkl
│   ├── classifier_v1.pkl
│   └── metadata.json
│
├── docs/
│   └── feature_selection.md
│
├── utils/
│   ├── __init__.py
│   ├── constants.py
│   ├── helper.py
│   ├── logger.py
│   └── validators.py
│
├── logs/
│   └── application.log
│
└── outputs/
    ├── cleaned_data.csv
    ├── enriched_data.csv
    ├── mapped_data.csv
    └── engineered_features.csv
```

---

# 🔄 Complete Data Pipeline

The backend processes security data through multiple stages.

## 1. Data Collection

Raw cybersecurity datasets are loaded from the configured data source.

Example data can contain:

* Security events
* Assets
* Vulnerabilities
* Threat intelligence
* Incidents
* Network information
* Indicators of compromise

The collected data is passed to the cleaning stage.

---

# 2. Data Cleaning

The cleaning module performs:

* Column name standardization
* Duplicate removal
* Empty row removal
* Duplicate column removal
* String cleaning
* Missing value handling
* Numeric value handling
* Date/time conversion
* Severity normalization

For example:

```text
critical → Critical
high     → High
medium   → Medium
low      → Low
```

The cleaned datasets are stored in:

```text
outputs/cleaned_data.csv
```

---

# 3. Threat Enrichment

Threat enrichment combines information from multiple sources.

Security events can be enriched with:

* Vulnerability information
* Threat intelligence
* CVSS score
* IOC information
* Exploit availability
* Threat IDs

The system calculates a threat score.

Example:

```text
CVSS = 8.5

Threat Score = 8.5 × 10
             = 85
```

Risk level:

```text
90–100 → Critical
70–89  → High
40–69  → Medium
0–39   → Low
```

The enriched dataset is saved as:

```text
outputs/enriched_data.csv
```

---

# 4. MITRE ATT&CK Mapping

The backend maps detected threats to MITRE ATT&CK techniques.

This allows the dashboard to show:

* MITRE technique
* Attack behavior
* Technique frequency
* Attack patterns

The mapped dataset is stored as:

```text
outputs/mapped_data.csv
```

---

# 5. Feature Engineering

Security events are transformed into machine-learning features.

Examples include:

* Severity
* Threat score
* CVSS score
* IOC match
* Known exploit
* Event frequency
* Asset information
* Threat intelligence indicators
* Network characteristics

The engineered dataset is stored as:

```text
outputs/engineered_features.csv
```

---

# 🤖 Machine Learning

The ML subsystem is located in:

```text
ml/
```

It contains separate components for preprocessing, feature selection, anomaly detection, classification, scoring, rules, explainability, evaluation, and model loading.

---

## ML Preprocessing

File:

```text
ml/preprocessing.py
```

Responsible for preparing data for machine-learning models.

Typical operations include:

* Missing value handling
* Encoding
* Scaling
* Feature transformation

---

## Feature Selection

File:

```text
ml/feature_selection.py
```

Selects the most useful features for ML models.

The documentation is available in:

```text
docs/feature_selection.md
```

---

# 🚨 Anomaly Detection

File:

```text
ml/anomaly_detection.py
```

The system uses anomaly detection to identify unusual security activity.

The trained model is:

```text
trained_models/isolation_forest_v1.pkl
```

Example:

```text
Normal Event
     ↓
Model
     ↓
Normal

Unusual Event
     ↓
Model
     ↓
Anomaly
```

Anomaly detection helps identify suspicious behavior that may not have previously known signatures.

---

# 🧠 ML Classification

File:

```text
ml/classifier.py
```

The classifier predicts the category of a security event.

Possible prediction categories depend on the trained model and application configuration.

The trained classifier is stored as:

```text
trained_models/classifier_v1.pkl
```

---

# 📊 Risk Scoring

The risk system combines security information to calculate a risk score.

Factors can include:

* Threat score
* ML prediction
* ML confidence
* Anomaly detection
* Vulnerability severity
* IOC match
* Exploit availability
* Threat intelligence
* Asset importance

Risk levels:

```text
Critical
High
Medium
Low
```

Risk-related functionality is handled by:

```text
services/risk_service.py
services/scoring_service.py
ml/scoring.py
ml/rules.py
routes/risk_routes.py
```

---

# 🔍 Explainability

File:

```text
ml/explainability.py
```

Provides reasons behind ML/risk predictions.

For example:

```text
Risk Score: 87

Reasons:
- Critical vulnerability detected
- Known exploit available
- Suspicious IOC matched
- Abnormal network behavior detected
```

This makes the system easier for security analysts to understand.

---

# 📈 Model Evaluation

File:

```text
ml/evaluation.py
```

Used to evaluate machine-learning model performance.

Depending on the model, evaluation can include:

* Accuracy
* Precision
* Recall
* F1-score
* Confusion matrix
* Anomaly detection performance

---

# 🧩 Model Loader

File:

```text
ml/model_loader.py
```

Responsible for loading trained models from:

```text
trained_models/
```

The models are not required to be retrained every time the Flask application starts.

---

# 🗃️ MongoDB Database

The backend uses MongoDB for persistent storage.

Database connection:

```text
database/mongodb.py
```

The database layer provides:

* MongoDB connection
* Database access
* Query functions
* Data insertion
* Prediction storage
* Incident storage

---

# 🔐 Environment Configuration

Create a `.env` file in the backend root.

Example:

```env
MONGO_USERNAME=threatadmin
MONGO_PASSWORD=YOUR_PASSWORD
MONGO_CLUSTER=YOUR_ACTUAL_CLUSTER.mongodb.net
MONGO_DATABASE=threat_detection

FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=True
```

Do **not** commit `.env` to GitHub.

Your `.gitignore` should contain:

```text
.env
__pycache__/
*.pyc
```

---

# 📦 Database Collections

The backend can work with collections such as:

```text
security_events
assets
vulnerabilities
threats
threat_intelligence
incidents
predictions
mitre
```

The exact documents stored depend on the data supplied to the application.

---

# 🧱 Database Queries

File:

```text
database/queries.py
```

Centralizes database operations such as:

* Getting security events
* Searching events
* Getting assets
* Getting vulnerabilities
* Getting threats
* Getting incidents
* Getting predictions
* Getting threat intelligence
* Getting MITRE techniques
* Getting risk statistics
* Getting top targeted assets
* Getting attack heatmap data
* Getting threat timeline data

This prevents database logic from being unnecessarily duplicated throughout the application.

---

# 💾 Prediction Repository

File:

```text
database/prediction_repository.py
```

Handles persistence of ML predictions.

Typical operations include:

```text
Save prediction
Get prediction
Update prediction
Find prediction by event
```

---

# 🚨 Incident Repository

File:

```text
database/incident_repository.py
```

Handles database operations for security incidents.

Typical operations include:

```text
Create incident
Get incident
Update incident
Find incidents
Update incident status
```

---

# 📦 Data Models

The `models/` directory defines the structure of backend entities.

## Asset

```text
models/asset_model.py
```

Represents a monitored asset.

---

## Vulnerability

```text
models/vulnerability_model.py
```

Represents vulnerability information.

---

## Threat

```text
models/threat_model.py
```

Represents detected threats.

---

## Security Event

```text
models/security_event_model.py
```

Represents individual security events.

---

## Incident

```text
models/incident_model.py
```

Represents security incidents.

It supports information such as:

```text
Incident ID
Asset ID
Event ID
Incident Type
Severity
Detected Time
Resolved Time
Status
Risk Score
Risk Level
Priority
ML Confidence
MITRE Technique
IOC Status
Recommendations
Related Events
Attack Chain
Reasons
```

---

## Prediction

```text
models/prediction_model.py
```

Represents ML prediction results.

It can store:

```text
Prediction ID
Event ID
Prediction
Confidence
Model Name
Model Version
Anomaly Score
Risk Score
Risk Level
Features
Explanation
Created Time
```

---

# ⚙️ Services Layer

The service layer contains the main business logic.

---

## Pipeline Service

```text
services/pipeline_service.py
```

Coordinates the complete data-processing pipeline.

Typical flow:

```text
Collection
    ↓
Cleaning
    ↓
Enrichment
    ↓
MITRE Mapping
    ↓
Feature Engineering
    ↓
ML Processing
    ↓
Risk Scoring
    ↓
Database
```

---

## Enrichment Service

```text
services/enrichment_service.py
```

Handles threat enrichment.

---

## MITRE Service

```text
services/mitre_service.py
```

Handles MITRE ATT&CK mapping and related operations.

---

## Feature Service

```text
services/feature_service.py
```

Handles feature engineering operations.

---

## Prediction Service

```text
services/prediction_service.py
```

Connects ML prediction functionality with the API/backend.

---

## Scoring Service

```text
services/scoring_service.py
```

Handles threat and risk score calculation.

---

## Analytics Service

```text
services/analytics_service.py
```

Provides dashboard analytics such as:

* Dashboard summary
* Risk distribution
* Incident status
* Threat timeline
* Attack heatmap
* Top targeted assets
* Threat types
* ML prediction statistics
* MITRE distribution

---

## Risk Service

```text
services/risk_service.py
```

Handles risk calculation and risk-related business logic.

---

## Incident Service

```text
services/incident_service.py
```

Handles incident creation, updates, prioritization, and management.

---

## Intelligence Service

```text
services/intelligence_service.py
```

Handles threat intelligence operations.

---

# 🌐 REST API Layer

The Flask API is implemented through the `routes/` directory.

---

# 📊 Analytics API

Base URL:

```text
/api/analytics
```

### Dashboard Summary

```http
GET /api/analytics/summary
```

Returns overall statistics.

---

### Complete Dashboard Analytics

```http
GET /api/analytics/dashboard
```

Returns combined dashboard information.

---

### Risk Distribution

```http
GET /api/analytics/risk
```

Returns:

```text
Critical
High
Medium
Low
```

counts.

---

### Incident Status

```http
GET /api/analytics/incidents/status
```

Returns incident counts by status.

---

### Threat Timeline

```http
GET /api/analytics/timeline
```

Optional:

```http
GET /api/analytics/timeline?days=30
```

Used to display security activity over time.

---

### Attack Heatmap

```http
GET /api/analytics/heatmap
```

Returns attack distribution between source and destination addresses.

---

### Top Targeted Assets

```http
GET /api/analytics/top-assets
```

Optional:

```http
GET /api/analytics/top-assets?limit=10
```

Returns assets receiving the highest number of security events.

---

### Threat Types

```http
GET /api/analytics/threat-types
```

Returns threat/event type distribution.

---

### ML Predictions

```http
GET /api/analytics/predictions
```

Returns prediction statistics.

---

### MITRE Distribution

```http
GET /api/analytics/mitre
```

Returns MITRE technique statistics.

---

# 🚨 Risk APIs

Routes:

```text
routes/risk_routes.py
```

These APIs expose risk-related functionality.

Typical functionality:

```text
Risk score
Risk level
Risk priority
Risk explanation
High-risk incidents
```

---

# 🤖 Prediction APIs

Routes:

```text
routes/prediction_routes.py
```

Used for ML predictions.

Typical flow:

```text
Security Event
      ↓
Feature Processing
      ↓
ML Model
      ↓
Prediction
      ↓
Confidence
      ↓
Risk Score
```

---

# 🚨 Anomaly APIs

Routes:

```text
routes/anomaly_routes.py
```

Used for anomaly detection.

The frontend can request anomaly results and display suspicious activity.

---

# 📝 Incident APIs

Routes:

```text
routes/incidents.py
routes/incident_routes.py
```

These provide incident management functionality.

Possible operations:

```text
Create incident
Get incidents
Get individual incident
Update incident
Update incident status
Get high-risk incidents
```

---

# 🧠 Threat Intelligence APIs

Routes:

```text
routes/intelligence_routes.py
```

Used for threat intelligence operations.

Examples:

```text
IOC lookup
Threat lookup
Threat actor information
Threat intelligence search
```

---

# 📤 CSV Export

File:

```text
routes/export.py
```

The backend supports exporting security data as CSV.

This allows the frontend to provide:

```text
Export CSV
```

functionality.

The backend retrieves the required data and converts it into a downloadable CSV response.

---

# 📄 PDF Report

The backend can generate security reports containing information such as:

```text
Dashboard summary
Risk statistics
Incident information
Threat statistics
Top targeted assets
Threat timeline
```

This supports the frontend feature:

```text
Download Report PDF
```

---

# 📊 Dashboard Features

The backend supports data required by the following dashboard features:

| Dashboard Feature      | Backend Responsibility      |
| ---------------------- | --------------------------- |
| Dark Mode              | Frontend                    |
| Export CSV             | Backend + Frontend          |
| Download Report PDF    | Backend + Frontend          |
| Search Event           | Backend + Frontend          |
| Threat Timeline        | Backend + Frontend          |
| Auto Refresh Dashboard | Backend provides fresh data |
| Heatmap of Attacks     | Backend + Frontend          |
| Top Targeted Assets    | Backend + Frontend          |
| Risk Distribution      | Backend + Frontend          |
| ML Prediction          | Backend                     |
| Anomaly Detection      | Backend                     |
| Incident Management    | Backend                     |
| Threat Intelligence    | Backend                     |
| MITRE Mapping          | Backend                     |

---

# 🔄 Dashboard Data Flow

The frontend does not directly perform database operations.

Instead:

```text
Frontend
   │
   │ HTTP Request
   ▼
Flask Route
   │
   ▼
Service Layer
   │
   ▼
Database Query
   │
   ▼
MongoDB
   │
   ▼
Service Processing
   │
   ▼
JSON Response
   │
   ▼
Frontend Dashboard
```

Example:

```text
Dashboard requests:

GET /api/analytics/top-assets

        ↓

analytics.py

        ↓

analytics_service.py

        ↓

database/queries.py

        ↓

MongoDB

        ↓

Top targeted assets

        ↓

JSON response

        ↓

Frontend chart
```

---

# 🔄 Auto Refresh

The backend does not continuously refresh the frontend by itself.

Instead, the frontend periodically requests updated data.

Example:

```text
Frontend
   ↓
GET /api/analytics/dashboard
   ↓
Backend
   ↓
MongoDB
   ↓
Latest statistics
   ↓
Frontend
```

The frontend can repeat this request every few seconds/minutes.

---

# 🔎 Search Event

Event search is performed through the backend.

Example:

```http
GET /api/.../search?query=192.168.1.10
```

The backend searches fields such as:

```text
Event ID
Event Type
Asset ID
Source IP
```

and returns matching events.

---

# 🗺️ Attack Heatmap

The backend generates data required for the frontend heatmap.

It groups attacks by:

```text
Source IP
Destination IP
Attack Count
```

Example:

```json
{
    "source_ip": "10.0.0.5",
    "destination_ip": "192.168.1.20",
    "count": 25
}
```

The frontend can then convert this information into a visual heatmap.

---

# 🎯 Top Targeted Assets

The backend groups security events by:

```text
asset_id
```

and counts the number of attacks.

Example:

```text
Server-01 → 120 attacks
Server-03 → 95 attacks
Database-01 → 81 attacks
```

This information can be displayed as a bar chart or ranking.

---

# 🕒 Threat Timeline

The backend groups security events by date.

Example:

```text
2026-08-25 → 35 events
2026-08-26 → 52 events
2026-08-27 → 48 events
2026-08-28 → 76 events
```

The frontend can display this as a line chart.

---

# 🛠️ Utility Layer

The `utils/` directory contains shared backend utilities.

```text
utils/constants.py
```

Contains application constants.

```text
utils/helper.py
```

Contains reusable helper functions.

```text
utils/logger.py
```

Handles application logging.

```text
utils/validators.py
```

Provides validation functions for incoming data.

---

# 📝 Logging

Application logs are stored in:

```text
logs/application.log
```

Logs can be used to track:

* Application startup
* API requests
* Database operations
* Errors
* Pipeline execution
* ML operations

---

# 📁 Generated Outputs

The pipeline can generate:

```text
outputs/
├── cleaned_data.csv
├── enriched_data.csv
├── mapped_data.csv
└── engineered_features.csv
```

These files represent different stages of processing.

---

# 📦 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/patelapaman/Data_Visulization_Backend_Team-B.git
```

Move into the backend directory:

```bash
cd Data_Visulization_Backend_Team-B
```

---

# 2. Create a Virtual Environment

Windows:

```bash
python -m venv venv
```

Activate it:

```bash
venv\Scripts\activate
```

---

# 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 4. Configure Environment Variables

Create:

```text
.env
```

Example:

```env
MONGO_USERNAME=threatadmin
MONGO_PASSWORD=YOUR_PASSWORD
MONGO_CLUSTER=YOUR_ACTUAL_CLUSTER.mongodb.net
MONGO_DATABASE=threat_detection

FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=True
```

---

# 5. Start the Backend

Run:

```bash
python app.py
```

The server should start at:

```text
http://127.0.0.1:5000
```

---

# 🧪 Testing the Backend

## Check Main API

Open:

```text
http://127.0.0.1:5000/
```

Expected response:

```json
{
    "success": true,
    "status": "running"
}
```

---

## Check API Health

Open:

```text
http://127.0.0.1:5000/api/health
```

Expected:

```json
{
    "success": true,
    "status": "healthy"
}
```

---

## Check Database

Open:

```text
http://127.0.0.1:5000/api/health/database
```

If MongoDB is correctly configured:

```json
{
    "success": true,
    "status": "connected"
}
```

---

## Check Dashboard Analytics

Open:

```text
http://127.0.0.1:5000/api/analytics/dashboard
```

This should return the dashboard analytics JSON.

---

# 🧰 Recommended API Testing Tools

You can test the backend using:

* Browser
* Postman
* Thunder Client
* curl
* Frontend application

For GET requests, a browser is sufficient for basic testing.

---

# 🔐 Security Considerations

Do not commit credentials to GitHub.

Never upload:

```text
.env
MongoDB passwords
API keys
Private credentials
```

Use environment variables instead.

Example:

```env
MONGO_PASSWORD=YOUR_PASSWORD
```

and access them using:

```python
os.getenv("MONGO_PASSWORD")
```

---

# 🧩 Error Handling

The Flask application provides API error handling for:

```text
404 → Endpoint not found
405 → Method not allowed
500 → Internal server error
```

Responses are returned in JSON format.

Example:

```json
{
    "success": false,
    "error": "Endpoint not found"
}
```

---

# 🧠 Complete Backend Workflow

The complete system can be summarized as:

```text
1. Collect Data
       ↓
2. Clean Data
       ↓
3. Enrich Threat Data
       ↓
4. Map MITRE ATT&CK
       ↓
5. Engineer Features
       ↓
6. Detect Anomalies
       ↓
7. Classify Threats
       ↓
8. Calculate Risk
       ↓
9. Generate Explanation
       ↓
10. Create/Update Incidents
       ↓
11. Store Results in MongoDB
       ↓
12. Expose REST APIs
       ↓
13. Frontend Requests Data
       ↓
14. Dashboard Displays Results
```

---

# 📌 Milestone 2 Features

The backend includes functionality for:

* Data cleaning
* Threat enrichment
* MITRE mapping
* Feature engineering
* MongoDB integration
* REST APIs
* Dashboard analytics
* Threat timeline
* Attack heatmap
* Top targeted assets
* CSV export
* PDF report generation
* Event search
* Dashboard data refresh

---

# 📌 Milestone 3 Features

The extended backend adds:

* Machine-learning prediction
* Anomaly detection
* ML confidence
* Risk scoring
* Risk levels
* Risk prioritization
* Explainable predictions
* Incident management
* Threat intelligence services
* Prediction repository
* Incident repository
* Advanced analytics
* MITRE-based analytics
* Model loading
* Model evaluation

---

# 🧪 Example Risk Flow

Suppose a security event contains:

```text
CVSS Score = 9.2
IOC Match = Yes
Known Exploit = Yes
Anomaly = Yes
ML Prediction = Malicious
ML Confidence = 94%
```

The backend processes this information:

```text
Security Event
      ↓
Threat Enrichment
      ↓
Feature Engineering
      ↓
Anomaly Detection
      ↓
ML Classification
      ↓
Risk Scoring
      ↓
Risk Level = Critical
      ↓
Incident Creation
      ↓
MongoDB
      ↓
Dashboard
```

The dashboard can then show:

```text
Risk Level: Critical
Prediction: Malicious
Confidence: 94%
IOC: Matched
Exploit: Available
```

# 👥 Backend Responsibility

This project is designed so that the backend is responsible for:

```text
Data
 ↓
Processing
 ↓
ML
 ↓
Threat Detection
 ↓
Risk Assessment
 ↓
Incident Management
 ↓
Database
 ↓
APIs
 ↓
Dashboard Data
```

The frontend is responsible for presenting the information visually.

For example:

```text
Backend:
"Server-01 received 120 attacks."

Frontend:
Displays a chart showing Server-01
as the most targeted asset.
```

---

# 📚 Main Technologies

| Technology             | Purpose                   |
| ---------------------- | ------------------------- |
| Python                 | Backend programming       |
| Flask                  | REST API framework        |
| Pandas                 | Data processing           |
| Scikit-learn           | Machine Learning          |
| Isolation Forest       | Anomaly detection         |
| MongoDB                | Database                  |
| PyMongo                | MongoDB integration       |
| NumPy                  | Numerical processing      |
| python-dotenv          | Environment configuration |
| Flask-CORS             | Cross-origin API access   |
| CSV                    | Data export               |
| PDF generation library | Report generation         |

---

# 📌 Important Files

### Application

```text
app.py
```

Main Flask application.

### Database

```text
database/mongodb.py
database/queries.py
```

MongoDB connection and queries.

### Machine Learning

```text
ml/anomaly_detection.py
ml/classifier.py
ml/scoring.py
ml/explainability.py
```

ML and security analysis.

### Services

```text
services/pipeline_service.py
services/analytics_service.py
services/prediction_service.py
services/risk_service.py
services/incident_service.py
services/intelligence_service.py
```

Business logic.

### Routes

```text
routes/analytics.py
routes/export.py
routes/prediction_routes.py
routes/anomaly_routes.py
routes/risk_routes.py
routes/incident_routes.py
routes/intelligence_routes.py
```

REST API endpoints.

---

# ✅ Final Result

The completed backend provides an end-to-end cybersecurity processing and threat-analysis system:

```text
                 RAW SECURITY DATA
                         │
                         ▼
                DATA COLLECTION
                         │
                         ▼
                  DATA CLEANING
                         │
                         ▼
                THREAT ENRICHMENT
                         │
                         ▼
                 MITRE ATT&CK
                         │
                         ▼
                FEATURE ENGINEERING
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
       ANOMALY DETECTION       ML CLASSIFIER
              │                     │
              └──────────┬──────────┘
                         ▼
                   RISK SCORING
                         │
                         ▼
                 EXPLAINABILITY
                         │
                         ▼
                INCIDENT MANAGEMENT
                         │
                         ▼
                     MONGODB
                         │
                         ▼
                   FLASK REST API
                         │
                         ▼
                 SECURITY DASHBOARD
```
>>>>>>> fef0746 (Milestone 3)
