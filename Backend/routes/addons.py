import csv
import io
from datetime import datetime

from flask import Blueprint, Response, g, jsonify, request
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from config import Config
from database.queries import build_event_filter, search_events
from services.addon_service import (
    heatmap_data,
    overview_analytics,
    threat_timeline,
    top_targeted_assets,
)

addons_bp = Blueprint("addons", __name__)


def _filters():
    return build_event_filter(
        search=request.args.get("q"),
        severity=request.args.get("severity"),
        event_type=request.args.get("event_type"),
        status=request.args.get("status"),
        country=request.args.get("country"),
        start_date=request.args.get("start_date"),
        end_date=request.args.get("end_date"),
    )


def _error(message, status_code=400):
    return (
        jsonify(
            {
                "status": "error",
                "error": {
                    "code": status_code,
                    "message": message,
                    "request_id": g.get("request_id"),
                },
            }
        ),
        status_code,
    )


@addons_bp.get("/api/events")
def search_events_api():
    """Search, filter, paginate and sort security events."""
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", request.args.get("limit", 50)))

        events, total, per_page = search_events(
            _filters(),
            page=page,
            per_page=per_page,
            sort_by=request.args.get("sort_by", "timestamp"),
            sort_order=request.args.get("sort_order", "desc"),
        )

        return jsonify(
            {
                "status": "success",
                "data": events,
                "pagination": {
                    "page": max(1, page),
                    "per_page": per_page,
                    "total": total,
                    "pages": (total + per_page - 1) // per_page,
                },
            }
        )

    except ValueError as exc:
        return _error(str(exc))


@addons_bp.get("/api/events/export.csv")
def export_events_csv():
    """Export filtered events as CSV."""
    try:
        events, total, _ = search_events(
            _filters(),
            page=1,
            per_page=Config.MAX_PAGE_SIZE,
            sort_by=request.args.get("sort_by", "timestamp"),
            sort_order=request.args.get("sort_order", "desc"),
        )

        fields = sorted({key for event in events for key in event.keys()})

        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)

        response = Response(stream.getvalue(), mimetype="text/csv")
        response.headers["Content-Disposition"] = (
            "attachment; filename=security-events.csv"
        )
        response.headers["X-Exported-Records"] = str(total)

        return response

    except ValueError as exc:
        return _error(str(exc))


@addons_bp.get("/api/analytics/overview")
def analytics_overview_api():
    return jsonify(
        {
            "status": "success",
            "data": overview_analytics(_filters()),
        }
    )


@addons_bp.get("/api/analytics/threat-timeline")
@addons_bp.get("/api/threat-timeline")
def threat_timeline_api():
    interval = request.args.get("interval", "day")

    if interval not in {"day", "month"}:
        return _error("interval must be either 'day' or 'month'")

    return jsonify(
        {
            "status": "success",
            "data": threat_timeline(_filters(), interval=interval),
        }
    )


@addons_bp.get("/api/analytics/top-targeted-assets")
@addons_bp.get("/api/top-targeted-assets")
def top_targeted_assets_api():
    try:
        limit = min(max(int(request.args.get("limit", 10)), 1), Config.MAX_PAGE_SIZE)
    except ValueError:
        return _error("limit must be an integer")

    return jsonify(
        {
            "status": "success",
            "data": top_targeted_assets(_filters(), limit=limit),
        }
    )


@addons_bp.get("/api/analytics/heatmap")
@addons_bp.get("/api/heatmap")
def heatmap_api():
    return jsonify(
        {
            "status": "success",
            "data": heatmap_data(_filters()),
        }
    )


@addons_bp.get("/api/reports/threats.pdf")
@addons_bp.get("/api/reports/pdf")
def threat_report_pdf():
    """Generate PDF report."""

    filters = _filters()

    analytics = overview_analytics(filters)
    timeline = threat_timeline(filters, interval="day")
    assets = top_targeted_assets(filters, limit=10)

    output = io.BytesIO()
    document = canvas.Canvas(output, pagesize=A4)

    width, height = A4
    y = height - 48

    def line(text, size=10, gap=16):
        nonlocal y

        if y < 48:
            document.showPage()
            y = height - 48

        document.setFont("Helvetica", size)
        document.drawString(42, y, str(text)[:115])
        y -= gap

    line(Config.API_TITLE, 16, 24)
    line(
        f"Generated: {datetime.utcnow().isoformat(timespec='seconds')} UTC",
        9,
        20,
    )

    line("Threat Analytics Summary", 13, 20)

    severity_text = ", ".join(
        f"{item['label']}={item['count']}"
        for item in analytics["severity"]
    )

    line(f"Severity: {severity_text}")

    event_text = ", ".join(
        f"{item['label']}={item['count']}"
        for item in analytics["event_types"]
    )

    line(f"Event types: {event_text}")

    line("Top targeted assets", 12, 20)

    for item in assets:
        line(
            f"{item['asset']} | "
            f"events={item['event_count']} | "
            f"critical={item['critical_events']} | "
            f"avg risk={item['average_risk_score']}"
        )

    line("Threat timeline", 12, 20)

    for item in timeline[-20:]:
        line(
            f"{item['period']} | "
            f"events={item['events']} | "
            f"high risk={item['high_risk_events']} | "
            f"critical={item['critical_events']}"
        )

    document.save()

    output.seek(0)

    response = Response(
        output.getvalue(),
        mimetype="application/pdf",
    )

    response.headers["Content-Disposition"] = (
        "attachment; filename=threat-report.pdf"
    )

    return response