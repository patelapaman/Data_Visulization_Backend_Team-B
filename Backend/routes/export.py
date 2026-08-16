from flask import Blueprint, Response
import pandas as pd

from database.queries import get_all_security_events

export_bp = Blueprint("export", __name__)


@export_bp.route("/csv", methods=["GET"])
def export_csv():
    """
    Export Security Events as CSV
    """

    data = get_all_security_events()

    if not data:
        return {
            "status": "error",
            "message": "No data found."
        }, 404

    df = pd.DataFrame(data)

    # Remove MongoDB ObjectId
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)

    csv_data = df.to_csv(index=False)

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=security_events.csv"
        }
    )