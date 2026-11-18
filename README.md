# Digital Forensics Evidence Analyzer (DFEA)

## Project Overview

The Digital Forensics Evidence Analyzer is a Python-based web application developed using Flask. It helps investigators manage digital evidence, verify file integrity, extract metadata, maintain chain-of-custody records, and generate forensic PDF reports.

## Objectives

- To simplify digital evidence management.
- To verify file integrity using SHA-256.
- To extract important file metadata.
- To maintain evidence handling records.
- To generate downloadable forensic reports.

## Features

1. **File Upload:** Upload digital evidence files.
2. **SHA-256 Hash Generation:** Generate a cryptographic hash for each uploaded file.
3. **Integrity Verification:** Identify changes by comparing stored and current hashes.
4. **Metadata Extraction:** Extract file name, size, type, creation date and modification date.
5. **Chain of Custody:** Record evidence-related actions, persons and timestamps.
6. **Dashboard:** Display evidence statistics and records.
7. **PDF Report Generation:** Generate reports containing evidence details and analysis results.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Flask | Backend web framework |
| SQLite | Database management |
| HTML and CSS | User interface |
| SHA-256 | File integrity verification |
| UUID | Unique file identification |
| ReportLab | PDF report generation |

## Algorithms Used

- **SHA-256:** Generates a cryptographic hash of the uploaded file.
- **Hash Comparison:** Compares the original and current hashes.
- **UUID:** Generates unique identifiers for stored filenames.

## Project Workflow

File Upload → Hash Generation → Metadata Extraction → Database Storage → Integrity Verification → Chain of Custody → PDF Report.

## Project Structure

```text
DFEA/
├── app.py
├── database.py
├── forensic.py
├── test_forensic.py
├── README.md
├── .gitignore
└── templates/
    ├── analysis.html
    ├── custody.html
    ├── dashboard.html
    ├── upload.html
    └── verification.html
```

## Installation and Execution

### 1. Clone the repository

```bash
git clone https://github.com/pavanreddyan33-ctr/DFEA.git
cd DFEA
```

### 2. Create a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install Flask reportlab
```

### 4. Run the application

```powershell
python app.py
```

### 5. Open in browser

```text
http://127.0.0.1:5000
```

## Future Enhancements

- AES-256 evidence encryption.
- Digital signatures for evidence authentication.
- Secure user authentication.
- Cryptographic protection for chain-of-custody records.
- Secure cloud-based evidence storage.

## Limitations

- The application detects changes made after the initial hash is generated.
- It cannot independently identify modifications made before uploading.
- Chain-of-custody records are stored in SQLite and are not tamper-proof.
- The application is an educational prototype and is not certified forensic software.
