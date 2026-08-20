# AI-Assisted Threat Detection Dashboard

A full-stack SOC (Security Operations Center) analyst dashboard: a React
frontend for monitoring and investigating security events, and a Flask +
MongoDB backend that processes security data and runs an AI/ML threat
detection engine (Isolation Forest anomaly detection + explainable hybrid
security rules).

This project is organized as **two independently deployable halves**
(matching the two separate GitHub repos used for this internship):

```
project/
├─ frontend/   React + Vite SPA           → push to the frontend repo
└─ backend/    Flask + MongoDB API        → push to the backend repo
```

They communicate purely over HTTP (REST) — the frontend calls the backend's
`/api/...` routes and never touches MongoDB or the ML model directly. Each
half can be developed, tested, and deployed on its own; see
`frontend/README.md` and `backend/README.md` for the full details on each.

---

## Quick start (run the whole thing locally)

You'll need: **MongoDB**, **Python 3.10+**, and **Node.js 18+**.

### 1. Database
Get MongoDB running first — everything else depends on it.
```bash
# Option A: Docker (simplest)
docker run -d -p 27017:27017 --name threat-mongo mongo:7

# Option B: install MongoDB Community Server locally and run `mongod`

# Option C: use a MongoDB Atlas cluster and put its connection string
#           in backend/.env as MONGO_URI
```

### 2. Backend
```bash
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```
This starts the API at `http://127.0.0.1:5000`. On first run it seeds
MongoDB from the bundled processed dataset.

### 3. Frontend
In a second terminal:
```bash
cd frontend
npm install
cp .env.example .env   # VITE_API_BASE_URL=http://127.0.0.1:5000/api
npm run dev
```
Open the printed URL (default `http://localhost:5173`). Register an
account, log in, and you'll land on the Overview dashboard with the AI
Threat Detection section available from the sidebar.

---

## What's in the dashboard

**Overview** — KPI cards, threat distribution / trend / attack-type
charts, a searchable and filterable security events table.

**AI Threat Detection** (Milestone 2) — anomaly predictions over the same
event dataset, an explainable "why was this flagged" investigation page
per event, a live prediction form, and model performance reporting.

**Account** — login/register, an editable profile page, and a settings
page with security/alert toggles and a Light/Dark/System theme picker
that's honored consistently across the whole app.

---

## Repo split for GitHub

Since this project lives in two separate repositories:

- Push the contents of `frontend/` (as the repo root) to the **frontend
  repo**.
- Push the contents of `backend/` (as the repo root) to the **backend
  repo**.
- Each has its own `README.md`, `.gitignore`, and `.env.example` — you
  don't need anything from outside its own folder to run it.

If you'd rather keep a combined repo, this root structure (frontend/ and
backend/ as sibling folders) already works as a monorepo — just make sure
`frontend/.env`'s `VITE_API_BASE_URL` points at wherever the backend ends
up deployed.

---

## Documentation

- `frontend/README.md` — frontend setup, project structure, and a
  changelog of the UI/UX pass (theme fixes, new Profile/Settings pages,
  etc.)
- `backend/README.md` — backend setup, environment variables, full API
  reference, and the ML pipeline summary
- `backend/docs/milestone2/` — feature selection, preprocessing, model
  evaluation, and API testing write-ups for the AI detection engine
