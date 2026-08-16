# 🛡️ AI-Assisted Threat Detection Dashboard

An intelligent cybersecurity backend designed to collect, process, analyze, and detect security threats using **Python, Flask, MongoDB, and Machine Learning**.

The system processes security data through multiple stages including **data cleaning, threat enrichment, MITRE ATT&CK mapping, feature engineering, anomaly detection, threat classification, risk scoring, and analytics**.

The processed information is stored in MongoDB and exposed through REST APIs for integration with a security monitoring dashboard.

---

## 🚀 Project Overview

Modern organizations generate large amounts of security data from:

- Security events
- Network activity
- Vulnerabilities
- Threat intelligence
- Assets
- Incidents
- Indicators of compromise (IOCs)

Manually analyzing all this information can be difficult and time-consuming.

This project provides an automated backend that:

1. Collects security datasets
2. Cleans and standardizes the data
3. Enriches security events with threat intelligence
4. Maps attacks to MITRE ATT&CK techniques
5. Generates machine-learning features
6. Detects anomalous behavior
7. Classifies potential threats
8. Calculates risk scores
9. Applies security rules
10. Generates explanations for predictions
11. Stores processed information in MongoDB
12. Provides REST APIs for the dashboard
13. Generates CSV and PDF reports
14. Provides analytics for security monitoring

---

# 🏗️ System Architecture

```text
                    SECURITY DATA
                         │
                         ▼
                ┌─────────────────┐
                │ Data Collection │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │  Data Cleaning  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │Threat Enrichment│
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │  MITRE Mapping  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │Feature Engineer.│
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Feature Selection│
                └────────┬────────┘
                         │
                         ▼
                  MACHINE LEARNING
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
       ┌──────────────┐      ┌──────────────┐
       │   Anomaly    │      │    Threat    │
       │  Detection   │      │ Classification│
       └──────┬───────┘      └───────┬──────┘
              │                      │
              └──────────┬───────────┘
                         ▼
                ┌─────────────────┐
                │  Threat Scoring │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Security Rules  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Explainability  │
                └────────┬────────┘
                         │
                         ▼
                   ┌───────────┐
                   │  MongoDB  │
                   └─────┬─────┘
                         │
                         ▼
                  ┌──────────────┐
                  │ Flask REST   │
                  │     APIs     │
                  └──────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │ Security      │
                 │ Dashboard     │
                 └───────────────┘
````

---

# ✨ Key Features

## 🔹 Data Collection

Loads security datasets from CSV files and prepares them for processing.

Supported data categories include:

* Security events
* Assets
* Vulnerabilities
* Threat intelligence
* Incidents
* MITRE ATT&CK information

---

## 🔹 Data Cleaning

The cleaning pipeline performs:

* Duplicate removal
* Missing-value handling
* Empty-row removal
* Column-name normalization
* String cleaning
* Numerical missing-value handling
* Date/time conversion
* Severity normalization

Example:

```text
Raw Data
   ↓
Remove duplicates
   ↓
Handle missing values
   ↓
Normalize columns
   ↓
Normalize severity
   ↓
Clean Dataset
```

Generated file:

```text
outputs/cleaned_data.csv
```

---

## 🔹 Threat Enrichment

Security events are enriched using vulnerability and threat-intelligence information.

The enrichment process can calculate:

* Threat score
* Risk level
* IOC match
* Known exploit status
* Enrichment status
* Vulnerability information
* Threat intelligence information

Risk levels:

|  Score | Risk        |
| -----: | ----------- |
| 90–100 | 🔴 Critical |
|  70–89 | 🟠 High     |
|  40–69 | 🟡 Medium   |
|   0–39 | 🟢 Low      |

Generated file:

```text
outputs/enriched_data.csv
```

---

# 🎯 MITRE ATT&CK Mapping

The system maps detected attacks to the **MITRE ATT&CK framework**.

The mapping can provide:

* Technique ID
* Technique name
* Attack category
* Tactic
* Description

Example:

```text
Security Event
      ↓
Attack Type
      ↓
MITRE Technique
      ↓
Technique ID
      ↓
Threat Analysis
```

Generated file:

```text
outputs/mapped_data.csv
```

---

# ⚙️ Feature Engineering

Feature engineering converts raw security information into numerical and categorical features that can be used by machine-learning models.

Examples include:

```text
failed_login_attempts
login_frequency
login_hour
connection_frequency
unique_destination_count
events_per_user
unique_ip_count
after_hours_activity
cvss_score
vulnerability_count
severity_score
malware_detected
event_frequency
impossible_travel_flag
threat_score
```

Additional risk-related features may include:

```text
failed_login_risk
behavioral_risk_score
combined_risk_score
high_cvss_flag
critical_cvss_flag
high_threat_flag
critical_threat_flag
```

Generated file:

```text
outputs/engineered_features.csv
```

---

# 🤖 Machine Learning

The project contains a dedicated ML layer:

```text
ml/
├── __init__.py
├── preprocessing.py
├── feature_selection.py
├── anomaly_detection.py
├── classifier.py
├── scoring.py
├── rules.py
├── explainability.py
├── evaluation.py
└── model_loader.py
```

---

## 🔍 Anomaly Detection

The project uses **Isolation Forest** for detecting unusual security behavior.

The model identifies events that differ significantly from normal activity.

Example:

```text
Normal Activity
     │
     ├── Few failed logins
     ├── Normal working hours
     └── Normal network activity
     
             VS

Anomalous Activity
     │
     ├── Large number of failed logins
     ├── Unusual login time
     ├── High connection frequency
     └── High threat score
```

---

# 🧠 Threat Classification

The classifier predicts the type or category of a security event based on engineered features.

Example:

```text
Security Event
      ↓
Feature Extraction
      ↓
Feature Selection
      ↓
ML Model
      ↓
Threat Prediction
```

Trained models are stored inside:

```text
trained_models/
```

---

# 📊 Threat Scoring

The scoring layer combines different security indicators to calculate the overall risk.

Factors can include:

* Threat score
* CVSS score
* Severity
* Anomaly result
* Failed login behavior
* Malware detection
* Security rules
* Behavioral indicators

Example:

```text
Threat Score
      +
Anomaly Detection
      +
Security Rules
      +
Behavioral Risk
      ↓
Final Risk Assessment
```

---

# 🧾 Explainability

The system can provide reasons behind a prediction.

Example:

```text
Prediction: Suspicious

Reasons:
• High number of failed login attempts
• High CVSS score
• Unusual activity time
• Multiple destination connections
```

This helps security analysts understand **why an event was considered suspicious**.

---

# 🗄️ MongoDB Database

MongoDB is used as the main database.

Database functionality is implemented in:

```text
database/
├── __init__.py
├── mongodb.py
├── insert_data.py
└── queries.py
```

Possible MongoDB collections include:

```text
assets
vulnerabilities
threats
security_events
incidents
mitre
predictions
model_performance
```

---

# 🌐 REST API

The backend uses **Flask** to expose REST APIs.

Main application:

```text
app.py
```

Routes are organized into separate modules.

```text
routes/
├── assets.py
├── vulnerabilities.py
├── threats.py
├── incidents.py
├── analytics.py
├── dashboard.py
├── prediction_routes.py
├── anomaly_routes.py
└── export.py
```

This keeps the application modular and easier to maintain.

---

# 📊 Dashboard Features

The backend provides data required by the frontend dashboard.

| Feature             | Backend  |
| ------------------- | :-----:  |
| Export CSV          |    ✅    |
| Download PDF Report |    ✅    |
| Search Event        |    ✅    |
| Threat Timeline     |    ✅    |
| Auto Refresh Data   |    ✅    |
| Attack Heatmap      |    ✅    |
| Top Targeted Assets |    ✅    |
| Threat Prediction   |    ✅    |
| Anomaly Detection   |    ✅    |
| Risk Scoring        |    ✅    |
| MITRE Mapping       |    ✅    |

The frontend is responsible for displaying the data visually.

---

# 📈 Analytics

The analytics service provides information for dashboard visualizations.

Examples:

### Threat Summary

```text
Critical: 12
High:     35
Medium:   71
Low:      120
```

### Threat Timeline

```text
Date          Threats
---------------------
Aug 10          20
Aug 11          35
Aug 12          42
Aug 13          28
```

### Top Targeted Assets

```text
Asset          Events
---------------------
SERVER-01        45
SERVER-04        32
SERVER-02        21
```

### Attack Heatmap

The backend aggregates attacks according to time/day information so the frontend can display a heatmap.

---

# 🔎 Event Search

The backend supports searching security events.

Possible search fields include:

```text
event_id
asset_id
threat_id
source_ip
destination_ip
event_type
severity
```

The database query layer handles the search while the route exposes it to the frontend.

---

# 📤 Export CSV

The export API allows processed security information to be downloaded as CSV.

Flow:

```text
Frontend
   ↓
Export API
   ↓
Database Query
   ↓
MongoDB
   ↓
CSV Generation
   ↓
Download
```

---

# 📄 PDF Reports

The backend supports security report generation using **ReportLab**.

A report can contain:

* Threat summary
* Risk distribution
* Recent security events
* Top targeted assets
* Threat timeline
* ML predictions
* Suspicious activities

Flow:

```text
Dashboard
    ↓
PDF API
    ↓
Analytics Service
    ↓
MongoDB
    ↓
Report Generation
    ↓
PDF
```

---

# 🔄 Auto Refresh

Auto refresh is primarily handled by the frontend.

The frontend periodically requests the latest backend data.

Example:

```text
Dashboard
    │
    │ Every 30 seconds
    ▼
GET /api/analytics/dashboard
    │
    ▼
MongoDB
    │
    ▼
Latest Data
```

The backend therefore always provides the latest available information.

---

# 📁 Project Structure

```text
backend/
│
├── data/
│
├── preprocessing/
│   ├── __init__.py
│   ├── data_collection.py
│   ├── data_cleaning.py
│   ├── threat_enrichment.py
│   ├── mitre_mapping.py
│   └── feature_engineering.py
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
├── database/
│   ├── __init__.py
│   ├── mongodb.py
│   ├── insert_data.py
│   └── queries.py
│
├── services/
│   ├── __init__.py
│   ├── pipeline_service.py
│   ├── enrichment_service.py
│   ├── mitre_service.py
│   ├── analytics_service.py
│   ├── feature_service.py
│   ├── prediction_service.py
│   └── scoring_service.py
│
├── routes/
│   ├── __init__.py
│   ├── assets.py
│   ├── vulnerabilities.py
│   ├── threats.py
│   ├── incidents.py
│   ├── analytics.py
│   ├── dashboard.py
│   ├── prediction_routes.py
│   ├── anomaly_routes.py
│   └── export.py
│
├── utils/
│   ├── __init__.py
│   ├── constants.py
│   ├── helper.py
│   ├── logger.py
│   └── validators.py
│
├── docs/
│   └── feature_selection.md
│
├── logs/
│   └── application.log
│
├── outputs/
│   ├── cleaned_data.csv
│   ├── enriched_data.csv
│   ├── mapped_data.csv
│   └── engineered_features.csv
│
├── config.py
├── app.py
├── requirements.txt
└── README.md
```

---

# 🛠️ Technologies Used

| Technology    | Purpose                        |
| ------------- | ------------------------------ |
| Python        | Backend programming            |
| Flask         | REST API framework             |
| Flask-CORS    | Frontend/backend communication |
| MongoDB       | Database                       |
| PyMongo       | MongoDB integration            |
| Pandas        | Data processing                |
| NumPy         | Numerical processing           |
| Scikit-learn  | Machine Learning               |
| Joblib        | ML model loading               |
| ReportLab     | PDF generation                 |
| Python-dotenv | Environment configuration      |

---

# 📦 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/patelapaman/Data_Visulization_Backend_Team-B.git
```

Move into the project:

```bash
cd Data_Visulization_Backend_Team-B
```

If the backend is inside a separate directory:

```bash
cd backend
```

---

## 2. Create Virtual Environment

### Windows

```bash
python -m venv venv
```

Activate:

```bash
venv\Scripts\activate
```

### Linux/macOS

```bash
python3 -m venv venv
```

Activate:

```bash
source venv/bin/activate
```

---

# 📥 Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🔐 MongoDB Configuration

Create a `.env` file in the backend directory.

```env
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/
MONGO_DATABASE=threat_detection
```

Replace the values with your MongoDB connection information.

> ⚠️ Never commit `.env` or database passwords to GitHub.

---

# ▶️ Running the Backend

Run:

```bash
python app.py
```

The Flask server should start at:

```text
http://127.0.0.1:5000
```

---

# ❤️ Health Check

Open:

```text
http://127.0.0.1:5000/health
```

The API should return information about the backend and MongoDB connection.

Example:

```json
{
    "success": true,
    "backend": "running",
    "mongodb": "connected"
}
```

---

# 🧪 API Health Check

Open:

```text
http://127.0.0.1:5000/api/health
```

Expected:

```json
{
    "success": true,
    "message": "API is working"
}
```

---

# 🔌 Example API Endpoints

## Dashboard

```text
GET /api/analytics/dashboard
```

## Analytics Summary

```text
GET /api/analytics/summary
```

## Threat Timeline

```text
GET /api/analytics/threat-timeline?days=7
```

## Attack Heatmap

```text
GET /api/analytics/attack-heatmap
```

## Top Targeted Assets

```text
GET /api/analytics/top-targeted-assets?limit=10
```

## Recent Predictions

```text
GET /api/analytics/recent-predictions?limit=20
```

## Model Performance

```text
GET /api/analytics/model-performance
```

## Prediction

```text
POST /api/predict
```

## Anomaly Detection

```text
POST /api/anomalies/detect
```

---

# 🧪 Example Prediction Request

```json
{
    "event": {
        "asset_id": "SERVER-001",
        "failed_login_attempts": 15,
        "cvss_score": 8.5,
        "malware_detected": false,
        "threat_score": 85
    }
}
```

The backend processes the event and returns a prediction containing information such as:

```json
{
    "prediction": "Suspicious",
    "risk_level": "High",
    "confidence_score": 87
}
```

---

# 📝 Logging

Application logs are stored in:

```text
logs/application.log
```

Logs can contain:

* Application startup information
* API activity
* Processing information
* Database errors
* ML errors
* Pipeline errors

---

# 📊 Generated Outputs

The preprocessing pipeline generates:

```text
outputs/
├── cleaned_data.csv
├── enriched_data.csv
├── mapped_data.csv
└── engineered_features.csv
```

These files allow developers to inspect the data after every major processing stage.

---

# 🔒 Security Considerations

The following files should not be committed to GitHub:

```text
.env
venv/
__pycache__/
*.pyc
```

Recommended `.gitignore`:

```gitignore
.env
venv/
.venv/
__pycache__/
*.pyc
*.pyo
*.log
.vscode/
.idea/
```

Production deployments should additionally use:

* Authentication
* Authorization
* API rate limiting
* HTTPS
* Secure database credentials
* Input validation
* Secure CORS configuration

---

# 🧭 Development Workflow

```text
1. Collect Data
       ↓
2. Clean Data
       ↓
3. Enrich Threats
       ↓
4. Map MITRE
       ↓
5. Engineer Features
       ↓
6. Select Features
       ↓
7. Run ML Models
       ↓
8. Calculate Risk
       ↓
9. Store in MongoDB
       ↓
10. Expose REST APIs
       ↓
11. Dashboard Visualization
```

---

# 🐙 Updating the GitHub Repository

If the project already exists on GitHub and you make changes locally:

```bash
git status
```

Add the changes:

```bash
git add .
```

Commit:

```bash
git commit -m "Update backend features"
```

Get the latest remote changes:

```bash
git pull --rebase origin main
```

Push:

```bash
git push origin main
```

If there are merge conflicts, resolve them and then continue the rebase.

---

# 🎯 Project Objective

The primary objective of this project is to build an intelligent cybersecurity backend that can transform raw security data into meaningful security intelligence.

The final workflow is:

```text
Raw Security Data
        ↓
Data Cleaning
        ↓
Threat Enrichment
        ↓
MITRE ATT&CK Mapping
        ↓
Feature Engineering
        ↓
Machine Learning
        ↓
Anomaly Detection
        ↓
Threat Classification
        ↓
Risk Scoring
        ↓
Explainable Results
        ↓
MongoDB
        ↓
REST APIs
        ↓
Security Dashboard
```

---

# 👥 Team

**Project:** AI-Assisted Threat Detection Dashboard

**Technology Stack:**

```text
Python
Flask
MongoDB
Pandas
NumPy
Scikit-learn
Joblib
ReportLab
REST APIs
```

---

# 📜 License

This project is developed for educational and project purposes.

Add an appropriate open-source license if the project is intended for public distribution.

```

This version is more suitable for GitHub because it gives a reviewer a clear **project overview → architecture → features → folder structure → ML pipeline → MongoDB → APIs → installation → usage → Git workflow** without making the README unnecessarily complicated.
```
