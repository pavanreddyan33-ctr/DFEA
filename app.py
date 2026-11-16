from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

import os
import sqlite3
import uuid
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from database import create_database
from forensic import calculate_hash, extract_metadata, verify_integrity


# --------------------------------------------------
# FLASK CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")
DATABASE_PATH = os.path.join(BASE_DIR, "forensics.db")

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_connection():
    return sqlite3.connect(DATABASE_PATH)


# Create database using the existing database module
os.chdir(BASE_DIR)
create_database()


# --------------------------------------------------
# FILE PATH HANDLING
# --------------------------------------------------

def get_full_path(stored_file):

    if not stored_file:
        return None

    if os.path.isabs(stored_file):
        return os.path.normpath(stored_file)

    return os.path.normpath(
        os.path.join(BASE_DIR, stored_file)
    )


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("upload.html")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, filename, stored_file, file_hash, upload_date
        FROM evidence
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    total = len(rows)
    verified = 0
    modified = 0
    unavailable = 0

    evidence_list = []

    for row in rows:

        evidence_id = row[0]
        filename = row[1]
        stored_file = row[2]
        original_hash = row[3]
        upload_date = row[4]

        full_path = get_full_path(stored_file)

        if full_path and os.path.isfile(full_path):

            current_hash = calculate_hash(full_path)

            status = verify_integrity(
                original_hash,
                current_hash
            )

        else:
            status = "UNAVAILABLE"

        if status == "VERIFIED":
            verified += 1

        elif status == "MODIFIED":
            modified += 1

        elif status == "UNAVAILABLE":
            unavailable += 1

        evidence_list.append((
            evidence_id,
            filename,
            upload_date,
            status
        ))

    return render_template(
        "dashboard.html",
        total=total,
        verified=verified,
        modified=modified,
        unavailable=unavailable,
        evidence_list=evidence_list
    )


# --------------------------------------------------
# UPLOAD EVIDENCE
# --------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload():

    if "evidence" not in request.files:
        return "No file selected"

    file = request.files["evidence"]

    if file.filename == "":
        return "No file selected"

    original_filename = secure_filename(file.filename)

    if not original_filename:
        return "Invalid filename"

    unique_id = str(uuid.uuid4())

    stored_filename = unique_id + "_" + original_filename

    full_path = os.path.join(
        UPLOAD_FOLDER,
        stored_filename
    )

    relative_path = os.path.join(
        "uploads",
        stored_filename
    )

    file.save(full_path)

    # Generate SHA-256 hash
    file_hash = calculate_hash(full_path)

    # Extract metadata
    metadata = extract_metadata(full_path)

    file_size = os.path.getsize(full_path)

    upload_date = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO evidence
        (filename, stored_file, file_hash, file_size, upload_date)
        VALUES (?, ?, ?, ?, ?)
    """, (
        original_filename,
        relative_path,
        file_hash,
        file_size,
        upload_date
    ))

    evidence_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO custody
        (evidence_id, action, person, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        evidence_id,
        "Evidence Uploaded and Hash Generated",
        "Admin",
        upload_date
    ))

    conn.commit()
    conn.close()

    return render_template(
        "analysis.html",
        evidence_id=evidence_id,
        filename=original_filename,
        file_hash=file_hash,
        metadata=metadata
    )


# --------------------------------------------------
# FILE INTEGRITY VERIFICATION
# --------------------------------------------------

@app.route("/verify/<int:evidence_id>")
def verify(evidence_id):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT filename, stored_file, file_hash
        FROM evidence
        WHERE id = ?
    """, (evidence_id,))

    record = cursor.fetchone()

    if record is None:
        conn.close()
        return "Evidence not found"

    filename = record[0]
    stored_file = record[1]
    original_hash = record[2]

    full_path = get_full_path(stored_file)

    if full_path and os.path.isfile(full_path):

        current_hash = calculate_hash(full_path)

        status = verify_integrity(
            original_hash,
            current_hash
        )

    else:
        current_hash = "File unavailable"
        status = "UNAVAILABLE"

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO custody
        (evidence_id, action, person, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        evidence_id,
        "Integrity Verification: " + status,
        "Admin",
        timestamp
    ))

    conn.commit()
    conn.close()

    return render_template(
        "verification.html",
        evidence_id=evidence_id,
        filename=filename,
        original_hash=original_hash,
        current_hash=current_hash,
        status=status
    )


# --------------------------------------------------
# CHAIN OF CUSTODY
# --------------------------------------------------

@app.route("/custody/<int:evidence_id>")
def view_custody(evidence_id):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT action, person, timestamp
        FROM custody
        WHERE evidence_id = ?
        ORDER BY id ASC
    """, (evidence_id,))

    records = cursor.fetchall()

    conn.close()

    return render_template(
        "custody.html",
        evidence_id=evidence_id,
        records=records
    )


# --------------------------------------------------
# GENERATE PDF FORENSIC REPORT
# --------------------------------------------------

@app.route("/generate_report/<int:evidence_id>")
def generate_report(evidence_id):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT filename, stored_file, file_hash,
               file_size, upload_date
        FROM evidence
        WHERE id = ?
    """, (evidence_id,))

    record = cursor.fetchone()

    if record is None:
        conn.close()
        return "Evidence not found"

    filename = record[0]
    stored_file = record[1]
    original_hash = record[2]
    file_size = record[3]
    upload_date = record[4]

    cursor.execute("""
        SELECT action, person, timestamp
        FROM custody
        WHERE evidence_id = ?
        ORDER BY id ASC
    """, (evidence_id,))

    custody_records = cursor.fetchall()

    conn.close()

    full_path = get_full_path(stored_file)

    # Verify file integrity
    if full_path and os.path.isfile(full_path):

        current_hash = calculate_hash(full_path)

        status = verify_integrity(
            original_hash,
            current_hash
        )

        metadata = extract_metadata(full_path)

    else:

        current_hash = "File unavailable"
        status = "UNAVAILABLE"

        metadata = {
            "File Name": filename,
            "File Size": file_size,
            "Created Date": "Unavailable",
            "Modified Date": "Unavailable",
            "File Type": os.path.splitext(filename)[1]
        }

    # PDF location
    report_name = f"Evidence_Report_{evidence_id}.pdf"

    report_path = os.path.join(
        REPORT_FOLDER,
        report_name
    )

    # Create PDF document
    doc = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["Normal"]

    hash_style = ParagraphStyle(
        "HashStyle",
        parent=normal_style,
        fontSize=7,
        leading=9,
        wordWrap="CJK"
    )

    elements = []

    # Report title
    elements.append(Paragraph(
        "DIGITAL FORENSICS EVIDENCE ANALYZER",
        title_style
    ))

    elements.append(Spacer(1, 10))

    elements.append(Paragraph(
        "Evidence Analysis Report",
        heading_style
    ))

    elements.append(Spacer(1, 15))

    # 1. Evidence details
    elements.append(Paragraph(
        "1. Evidence Details",
        heading_style
    ))

    evidence_data = [
        ["Evidence ID", str(evidence_id)],
        ["File Name", filename],
        ["File Size", str(file_size) + " bytes"],
        ["Upload Date", str(upload_date)]
    ]

    evidence_table = Table(
        evidence_data,
        colWidths=[120, 395]
    )

    evidence_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    elements.append(evidence_table)

    elements.append(Spacer(1, 15))

    # 2. Integrity verification
    elements.append(Paragraph(
        "2. File Integrity Verification",
        heading_style
    ))

    hash_data = [
        [
            "Original SHA-256 Hash",
            Paragraph(escape(str(original_hash)), hash_style)
        ],
        [
            "Current SHA-256 Hash",
            Paragraph(escape(str(current_hash)), hash_style)
        ],
        ["Integrity Status", status]
    ]

    hash_table = Table(
        hash_data,
        colWidths=[150, 365]
    )

    hash_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    elements.append(hash_table)

    elements.append(Spacer(1, 15))

    # 3. File metadata
    elements.append(Paragraph(
        "3. File Metadata",
        heading_style
    ))

    metadata_data = [["Property", "Value"]]

    for key, value in metadata.items():
        metadata_data.append([
            str(key),
            str(value)
        ])

    metadata_table = Table(
        metadata_data,
        colWidths=[150, 365]
    )

    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    elements.append(metadata_table)

    elements.append(Spacer(1, 15))

    # 4. Chain of custody
    elements.append(Paragraph(
        "4. Chain of Custody",
        heading_style
    ))

    custody_data = [
        ["Action", "Person", "Timestamp"]
    ]

    for item in custody_records:
        custody_data.append([
            str(item[0]),
            str(item[1]),
            str(item[2])
        ])

    custody_table = Table(
        custody_data,
        colWidths=[190, 100, 225]
    )

    custody_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    elements.append(custody_table)

    elements.append(Spacer(1, 20))

    elements.append(Paragraph(
        "Report Generated: " +
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        normal_style
    ))

    elements.append(Spacer(1, 10))

    elements.append(Paragraph(
        "Note: This report is generated by a prototype "
        "Digital Forensics Evidence Analyzer.",
        normal_style
    ))

    doc.build(elements)

    return send_file(
        report_path,
        as_attachment=True
    )


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
