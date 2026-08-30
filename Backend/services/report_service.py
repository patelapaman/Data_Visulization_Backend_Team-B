import os

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet

from database.queries import get_dashboard_summary


def generate_pdf_report():

    os.makedirs("outputs", exist_ok=True)

    pdf_file = "outputs/Threat_Report.pdf"

    document = SimpleDocTemplate(pdf_file)

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph(
            "AI-Assisted Threat Detection Dashboard",
            styles["Title"]
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Threat Analysis Report",
            styles["Heading2"]
        )
    )

    story.append(Spacer(1, 10))

    summary = get_dashboard_summary()

    for key, value in summary.items():

        story.append(
            Paragraph(
                f"<b>{key}</b> : {value}",
                styles["BodyText"]
            )
        )

        story.append(Spacer(1, 5))

    document.build(story)

    return pdf_file