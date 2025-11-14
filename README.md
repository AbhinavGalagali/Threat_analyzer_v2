________________________________________
🛡️ Threat Intelligence Extraction Script

A Python-based automated tool for extracting cyber threat intelligence from unstructured documents.
It supports PDF, DOCX, and TXT formats and uses a hybrid approach combining regex, SpaCy NER, and transformer-based models to extract IoCs, TTPs, malware names, threat actors, and targeted entities.
The tool can run through a CLI or an integrated web-based dashboard for simplified file upload, filtering, and downloading results.
________________________________________
📌 Features

🔍 Automated Threat Intelligence Extraction

Extracts a wide range of threat intelligence elements including:
•	Indicators of Compromise (IoCs):
o	IP addresses
o	MAC addresses
o	Domains and URLs
o	File hashes (MD5, SHA-1, SHA-256)
o	Email addresses
o	Windows registry keys
o	File paths
o	GUIDs
o	Filenames
•	TTPs (Tactics, Techniques, Procedures):
o	Identifies MITRE ATT&CK tactics
o	Matches known techniques by ID (e.g., T1566)
•	Malware Names:
o	Extracts potential malware names
o	Optional enrichment using VirusTotal API
•	Threat Actors:
o	Detects threat actor names using transformers and NER
•	Targeted Entities:
o	Industries, organizations, and related entities extracted via NER
________________________________________
📦 Requirements

🔑 Key Dependencies

Ensure the following libraries are installed:
•	PyMuPDF – PDF text extraction
•	docx2txt – DOCX text extraction
•	spacy – Named Entity Recognition
•	transformers – Transformer-based NER & classification
•	requests – API calls (e.g., VirusTotal)
•	werkzeug – Secure filename handling
•	pathlib, json, re, datetime – core utility libraries
All dependencies are included in requirements.txt.

📝 Input Requirements

•	File formats: PDF, DOCX, TXT
•	PDFs must be machine-readable (OCR required for scanned documents)
•	Avoid documents with heavy images, charts, tables, as they reduce extraction accuracy
•	Can process:
o	A single file
o	A folder containing multiple supported files
📤 Output
•	Each input file generates a corresponding JSON output:
output_<filename>.json
•	Saved in the same directory as the input file(s)
________________________________________
▶️ How to Run

1. Install Dependencies
pip install -r requirements.txt
2. Prepare Input Files
•	Ensure files are machine-readable
•	For scanned PDFs → Use OCR tools such as Tesseract or Adobe Acrobat
3. Run via Command Line
Save your script as:
threat_extractor.py
Then execute:
python threat_extractor.py
Follow the prompts to enter a file or folder path.
________________________________________
🌐 Web-Based Dashboard

Access the dashboard (URL provided separately) to:
•	Upload single/multiple files
•	View extracted intelligence in real time
•	Filter & sort extracted IoCs, TTPs, malware names, actors, and more
•	Download results in JSON format
•	Enjoy an interactive, user-friendly interface
________________________________________
🧠 Extraction Logic

1. Regex-Based Extraction
Used for structured elements such as:
•	IP addresses
•	Domains and URLs
•	Hashes
•	Registry paths
•	GUIDs
•	Email addresses
•	File paths and filenames
2. SpaCy NER
Used to extract:
•	Organizations
•	Persons
•	Malware families
•	Threat actor references
3. Transformer Models
Enhances recognition of:
•	Threat actors
•	Targeted entities
•	Contextual classification
4. MITRE ATT&CK Mapping
•	Predefined list of tactics/techniques
•	Matches IDs like T1566, Initial Access, etc.
________________________________________
🧹 Dataset Preprocessing

For Scanned PDFs
Use OCR tools like:
•	Tesseract
•	Adobe Acrobat OCR
Text Cleaning
•	Remove noise, extra whitespace, special characters
•	Normalize extracted text before analysis
________________________________________
⚠️ Limitations

•	OCR dependency: Scanned PDFs require preprocessing
•	Layout sensitivity: Complex formatting can lower accuracy
•	Regex limitations: May cause false positives or negatives
•	MITRE updates: Technique mappings require periodic updates
________________________________________
🚀 Future Improvements

•	Automated enrichment via external APIs (VirusTotal, Recorded Future, etc.)
•	Expand NER training datasets
•	Improve regex coverage for niche IoC types
•	More robust transformer models for threat actor identification
________________________________________


