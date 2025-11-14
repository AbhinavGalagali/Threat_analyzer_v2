import os
from pathlib import Path
import fitz
import spacy
import requests
import re
import json
from werkzeug.utils import secure_filename  # <-- Required import
from datetime import datetime
import uuid

# Load the SpaCy model for Named Entity Recognition
nlp = spacy.load("en_core_web_sm")

# Function to determine single PDF path or folder path
def extract_threat_info_from_path(path_input):
    
    if path_input.is_file():
        process_pdf(path_input)
    elif path_input.is_dir():
        for pdf_path in path_input.glob("*.pdf"):
            process_pdf(pdf_path)
    else:
        print("Error: Invalid path (neither file nor directory).")

#  Processes a single PDF, extracts information, and saves to a JSON file
def process_pdf(pdf_path):
    try:
        text = extract_text_from_pdf(pdf_path)
        if not text.strip():
            print(f"Warning: {pdf_path.name} contains no extractable text.")
            return

        threat_data = extract_threat_data(text)
        
        # Generate secure output filename
        original_stem = secure_filename(pdf_path.stem)
        output_filename = f"output_{original_stem}.json"
        output_path = pdf_path.parent / output_filename  

        # Add metadata
        threat_data.update({
            'original_filename': pdf_path.name,
            'report_filename': output_filename,
            'timestamp': datetime.now().isoformat(),
            'report_id': f"RPT-{uuid.uuid4().hex[:8].upper()}"
        })

        with open(output_path, 'w', encoding='utf-8') as json_file:
            json.dump(threat_data, json_file, indent=4, ensure_ascii=False)

        print(f"Report generated: {output_path}")

    except Exception as e:
        print(f"Critical error processing {pdf_path.name}: {e}")

# Extracts text from a PDF file
def extract_text_from_pdf(pdf_path):
    
    text = ""
    try:
        with fitz.open(pdf_path) as pdf_document:
            for page in pdf_document:
                text += page.get_text()
    except Exception as e:
        print(f"Error extracting text from {pdf_path.name}: {e}")
    return text

# Processing PDF file path or a folder path containing PDFs
def get_pdf_path_or_folder(prompt):
    while True:
        path_str = input(prompt)
        path = Path(path_str)

        if not path.exists():
            print("Error: Path does not exist.")
            continue

        if path.is_file():
            if path.suffix.lower() == ".pdf":
                return path
            else:
                print("Error: Not a PDF file.")
                continue
        elif path.is_dir():
            if any(p.suffix.lower() == ".pdf" for p in path.iterdir() if p.is_file()):
                return path
            else:
                print("Error: Folder does not contain any PDF files.")
                continue
        else:
            print("Error: Invalid path (neither file nor directory).")

# Extracts all threat-related information from the given text
def extract_threat_data(text):
    threat_data = {}

    threat_data['IoCs'] = extract_iocs(text)
    threat_data['TTPs'] = extract_ttps(text)
    threat_data['Malware'] = extract_malware(text)
    threat_data['Threat Actors'] = extract_threat_actors(text)
    threat_data['Targeted Entities'] = extract_targeted_entities(text)

    return threat_data

# MITRE ATT&CK framework mapping: Tactics and their corresponding technique IDs
mitre_attack_mapping = {
    "Reconnaissance": {
        "Active Scanning": "T1595",
        "Gather Victim Host Information": "T1592",
        "Phishing for Information": "T1598",
        "Search Open Technical Databases": "T1596",
        "Gather Victim Identity Information": "T1589",
        "Gather Victim Org Information": "T1590",
        "Gather Victim Network Information": "T1591",
        "Passive Scanning": "T1595.002"
    },
    "Resource Development": {
        "Obtain Capabilities": "T1587",
        "Compromise Infrastructure": "T1584",
        "Develop Capabilities": "T1588",
        "Establish Accounts": "T1585",
        "Obtain Access": "T1583"
    },
    "Initial Access": {
        "Drive-by Compromise": "T1189",
        "Exploit Public-Facing Application": "T1190",
        "Phishing": "T1566",
        "Spear Phishing Attachment": "T1566.001",
        "Spear Phishing Link": "T1566.002",
        "Initial Access": "TA0001",
        "Trusted Relationship": "T1199",
        "Valid Accounts": "T1078",
        "External Remote Services": "T1133"

    },
    "Execution": {
        "Command and Scripting Interpreter": "T1059",
        "Scheduled Task/Job": "T1053",
        "Exploitation for Client Execution": "T1203",
        "Execution": "TA0002",
        "User Execution": "T1204",
        "PowerShell": "T1059.001",
        "Windows Command Shell": "T1059.003"
    },
    "Persistence": {
        "Account Manipulation": "T1098",
        "Create or Modify System Process": "T1543",
        "Scheduled Task/Job": "T1053",
        "Create Account": "T1136",
        "Logon Scripts": "T1037",
        "Registry Run Keys / Startup Folder": "T1547"

    },
    "Privilege Escalation": {
        "Exploitation for Privilege Escalation": "T1068",
        "Process Injection": "T1055",
        "Valid Accounts": "T1078",
        "Bypass User Account Control": "T1088",
        "Process Discovery": "T1057",
        "Access Token Manipulation": "T1134"
    },
    "Defense Evasion": {
        "Obfuscated Files or Information": "T1027",
        "Masquerading": "T1036",
        "Disable or Modify Tools": "T1562",
        "Indicator Removal on Host": "T1070",
        "File Deletion": "T1107",
        "Hidden Files or Directories": "T1564"
    },
    "Credential Access": {
        "Brute Force": "T1110",
        "Credential Dumping": "T1003",
        "OS Credential Dumping": "T1003.001",
        "Input Capture": "T1056",
        "Credential Access": "TA0006",
        "Man-in-the-Middle": "T1557"
    },
    "Discovery": {
        "System Network Configuration Discovery": "T1016",
        "System Network Connections Discovery": "T1049",
        "Account Discovery": "T1087",
        "File and Directory Discovery": "T1083",
        "Query Registry": "T1012",
        "Remote System Discovery": "T1018"
    },
    "Lateral Movement": {
        "Remote Services": "T1021",
        "Exploitation of Remote Services": "T1210",
        "Remote Desktop Protocol": "T1021.001",
        "Lateral Movement": "TA0008",
        "Pass the Hash": "T1550",
        "Pass the Ticket": "T1550.003",
        "Windows Remote Management": "T1021.006"
    },
    "Collection": {
        "Screen Capture": "T1113",
        "Input Capture": "T1056",
        "Data from Local System": "T1005",
        "Data Staging": "T1074",
        "Automated Collection": "T1119",
        "Data from Network Shared Drive": "T1039"
    },
    "Command and Control": {
        "Application Layer Protocol": "T1071",
        "Non-Standard Port": "T1571",
        "Fallback Channels": "T1008",
        "Web Protocols": "T1071.001",
        "DNS": "T1071.004",
        "Command and Control": "TA0011"
    },
    "Exfiltration": {
        "Exfiltration Over Web Service": "T1567",
        "Exfiltration Over C2 Channel": "T1041",
        "Data Encrypted for Impact": "T1486",
        "Exfiltration to Cloud Storage": "T1567.002",
        "Scheduled Transfer": "T1020",
        "Exfiltration over Alternative Protocol": "T1048"
    },
    "Impact": {
        "Data Manipulation": "T1565",
        "Disk Wipe": "T1561",
        "Endpoint Denial of Service": "T1499",
        "Data Destruction": "T1485",
        "Data Encrypted for Impact": "T1486",
        "Resource Hijacking": "T1496"

    }
}

# Function to extract Indicators of Compromise (IoCs) from the text
def extract_iocs(text):
    iocs = {
        'IP Addresses': re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text),
        'MAC Addresses': re.findall(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', text),
        'Domains': re.findall(r'\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+[a-zA-Z]{2,}\b', text),
        'MD5 Hashes': re.findall(r'\b[a-fA-F0-9]{32}\b', text),
        'SHA-1 Hashes': re.findall(r'\b[a-fA-F0-9]{40}\b', text),
        'SHA-256 Hashes': re.findall(r'\b[a-fA-F0-9]{64}\b', text),
        'SHA-512 Hashes': re.findall(r'\b[a-fA-F0-9]{128}\b', text),
        'Emails': re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text),
        'URLs': re.findall(r'https?://(?:www\.)?[-a-zA-Z0-9@:%.\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%\+.~#?&//=]*)', text),
        'Registry Keys': re.findall(r'HKEY(?:_LOCAL_MACHINE|_CURRENT_USER|_CLASSES_ROOT|_USERS|_DYN_DATA)\\(?:[^\\]+\\)*[^\\]+', text),
        'File Paths (Windows)': re.findall(r'[A-Za-z]:\\(?:[^\\/:?"<>|]+\\)[^\\/:*?"<>|]+', text),
        'GUIDs': re.findall(r'{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}', text),
        'Filenames': re.findall(r'\b[a-zA-Z0-9_.-]+\.(?:exe|ocx|cpl|gen|xml|dll|sys|bat|ps1|vbs|zip|rar|7z|pdf|doc|docx|xls|xlsx|txt|jpg|png|gif)\b', text, re.IGNORECASE)
    }

    # Separate domains from file paths and filter out file-like domains
    domains = iocs.pop('Domains', [])
    file_paths = iocs.get('File Paths (Windows)', [])
    actual_domains = []
    file_extensions_regex = r'\.(?:exe|ocx|cpl|gen|xml|dll|sys|bat|ps1|vbs|zip|rar|7z|pdf|doc|docx|xls|xlsx|txt|jpg|png|gif)\b'

    for domain in domains:
        if not any(domain in path for path in file_paths) and not re.search(file_extensions_regex, domain, re.IGNORECASE):
            actual_domains.append(domain)

    iocs['Domains'] = list(set(actual_domains))
    return {k: list(set(v)) for k, v in iocs.items() if v}


# Function to extract TTPs from the text
def extract_ttps(text):
    ttps = []
    for tactic, techniques in mitre_attack_mapping.items():
        for technique, technique_id in techniques.items():
            # Case-insensitive matching for tactic, technique names, or technique IDs
            if re.search(technique, text, re.IGNORECASE) or re.search(technique_id, text, re.IGNORECASE):
                ttps.append({'tactic': tactic, 'technique': technique, 'technique_id': technique_id})

    return ttps

# Known malware list
known_malware = [
    "Shamoon", "WannaCry", "Emotet", "Ryuk", "TrickBot", "NotPetya",
    "Mirai", "Stuxnet", "Zeus", "Conficker", "CryptoLocker",
    "Agent Tesla", "Ursnif", "Dridex", "Qbot", "QakBot",
    "GandCrab", "Maze", "Sodinokibi", "REvil", "LockBit",
    "Conti", "BlackCat", "Ragnar Locker", "Vice Society",
    "Cerber", "Jigsaw", "Petya", "Bad Rabbit", "GoldenEye", "Wiper",
    "Adwind", "njRAT", "DarkComet", "Remcos", "Netwire",
    "Gh0st RAT", "PoisonIvy", "XtremeRAT", "Nanocore", "Imminent Monitor",
    "Ursnif", "IcedID", "Emotet", "Dridex", "TrickBot", "Qbot", "Buer Loader",
    "Zeus Panda", "Gozi", "Citadel", "Ramnit", "Carberp",
    "Duqu", "Flame", "Gauss", "Red October", "Turla", "Equation Group Tools",
    "APT1", "APT28", "APT29", "APT32", "APT33", "APT41", "Lazarus Group", "Sandworm Team", "Fancy Bear", "Cozy Bear",
    "Cobalt Strike", "Metasploit", "Mimikatz", "PowerShell Empire", "BloodHound",
    "Formbook", "AZORult", "RedLine Stealer", "Vidar Stealer", "Predator the Thief",
    "Agent Smith", "HummingBad", "xHelper", "Triada", "LokiBot",
    "Kryptik", "Zbot", "SpyEye", "Tinba", "Shylock",
    "Ryuk", "Maze", "Conti", "LockBit", "Black Basta", "Hive", "Clop", "Avaddon", "Egregor",
    "TrickBot", "Dridex", "Emotet", "QakBot", "IcedID", "Buer Loader", "Zloader", "Gozi", "Ursnif"
]

# Function to extract malware names using spaCy NLP
def extract_malware(text):
    # Use spaCy NLP to process the text
    doc = nlp(text)

    # Use spaCy Named Entity Recognition (NER) to find potential malware names
    malware_names_found = set()
    for ent in doc.ents:
        # Check if the entity is in the known malware list or matches a pattern
        if ent.text in known_malware or is_potential_malware(ent.text):
            malware_names_found.add(ent.text)

    # Extract metadata for each identified malware name
    malware_info = []
    for name in malware_names_found:
        metadata = get_malware_metadata(name)
        if metadata == 0:  # Skip if an error is detected
            continue
        else:
            malware_info.append(metadata)

    return malware_info

# Check if a string is a potential malware name based on patterns
def is_potential_malware(name):
    malware_pattern = r'\b[A-Za-z0-9._-]{4,}\b'
    return bool(re.match(malware_pattern, name))

# Get metadata for a given malware name from VirusTotal
def get_malware_metadata(malware_name):
    api_key = '260bdfa59ee6346cd4f66dd2fefbcd5a57eb482044d2f676050783bf82a95baf'
    url = f'https://www.virustotal.com/api/v3/files/{malware_name}'
    headers = {'x-apikey': api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Extract relevant metadata
        attributes = data.get("data", {}).get("attributes", {})
        malware_details = {
            "Name": malware_name,
            "md5": attributes.get("md5", "N/A"),
            "sha1": attributes.get("sha1", "N/A"),
            "sha256": attributes.get("sha256", "N/A"),
            "ssdeep": attributes.get("ssdeep", "N/A"),
            "TLSH": attributes.get("tlsh", "N/A"),
            "tags": attributes.get("tags", [])
        }
        return malware_details
    except requests.exceptions.RequestException:
        return 0  # Could not retrieve metadata

# Function to extract threat actors from the text
def extract_threat_actors(text):
    known_threat_actors = [
        "APT1", "APT28", "APT29", "APT32", "APT33", "APT41", "Lazarus Group", "Sandworm Team",
        "Equation Group", "Charming Kitten", "Turla", "FIN7", "TA505", "DarkHydrus", "MuddyWater",
        "Mustang Panda", "Kimsuky", "APT40", "APT19", "APT5", "Carbanak Group", "REvil", "LockBit", #Added some more
        "Lapsus$", "Conti", "BlackCat", "Ragnar Locker", "Vice Society" #Added some more
    ]
    doc = nlp(text)
    extracted_actors = []

    # Direct string matching (fastest for known actors)
    for actor in known_threat_actors:
        if actor in text:
            extracted_actors.append(actor)

    # Regex matching for variations and related terms (e.g., "APT 28")
    for actor in known_threat_actors:
        # Create regex that handles spaces, hyphens, etc.
        regex_actor = r"\b" + re.escape(actor.replace(" ", r"\s*").replace("-", r"[-–—]?")) + r"\b" #Improved regex
        matches = re.findall(regex_actor, text, re.IGNORECASE)
        extracted_actors.extend(matches)

    # Use spaCy's NER to find potential organization mentions (ORG) and check if they match known actors (more general approach)
    for ent in doc.ents:
        if ent.label_ == "ORG":
            for actor in known_threat_actors:
                if actor.lower() in ent.text.lower(): #Case insensitive check
                    extracted_actors.append(actor)

    # Look for common threat actor keywords and phrases (more general approach)
    threat_keywords = [
      r"\bAPT(?:\s[0-9]+)?\b",  # Matches "APT" and variations like "APT 29"
      r"\b(?:Advanced Persistent Threat|Advanced Persistent Threats)\b",  # Matches full phrase for APT
      r"\b(?:Cybercriminal|Cybercriminals|Cyber Crime Gang|Cyber Espionage Group)\b",  # Broader cybercriminal terms
      r"\b(?:Threat Actor|Threat Actors|Malicious Actor|Malicious Actors)\b",  # Variations of "Threat Actor"
      r"\b(?:Hacker|Hackers|Hacking Group|Hacker Group)\b",  # Covers hacker-related terms
      r"\b(?:Group|Team|Cybercrime Team|Hacking Team)\b",  # Matches groups or teams
      r"\b(?:Adversary|Adversaries)\b",  # Matches "Adversary" or "Adversaries"
      r"\b(?:Nation-State Actor|Nation-State Actors|State-Sponsored Actor|State-Sponsored Actors)\b",  # Nation-state attackers
      r"\b(?:Ransomware Gang|Ransomware Group)\b",  # Specific to ransomware-related groups
      r"\b(?:Espionage Group|Cyber Espionage Actor|APT Group)\b",  # Espionage-related actors
      r"\b(?:Insider Threat|Internal Actor|Insider)\b",  # Covers insider threats
      r"\b(?:Hacktivist|Hacktivists|Hacktivism Group)\b",  # Matches hacktivist groups
      r"\b(?:Cyber Syndicate|Criminal Network|Hacking Syndicate)\b",  # Organized cybercrime groups
      r"\b(?:Actor|Actors|Campaign)\b"  # Generic threat actor terms
    ]

    for keyword in threat_keywords:
        if re.search(keyword, text, re.IGNORECASE):
            # If a keyword is found, do additional checks to see if it's related to a specific actor
            for ent in doc.ents:
                if ent.label_ == "ORG":
                    for actor in known_threat_actors:
                        if actor.lower() in ent.text.lower():
                            extracted_actors.append(actor)


    extracted_actors = list(set(extracted_actors))
    return extracted_actors if extracted_actors else ["Unknown"]


# Function to extract targeted entities from the text
def extract_targeted_entities(text):
    doc = nlp(text)
    targeted_entities = []

    # Look for entities after phrases like "targeting," "attacks against," "compromise of" using regex
    regex_patterns = [
    # Matches "targeting," "attacks against," "compromise of," "focused on," "aimed at," and "directed at," capturing entities after these phrases.
    r"(?:targeting|attacks against|compromise of|focused on|aimed at|directed at)\s((?:the\s)?[\w\s-]+?)(?:\.|,|\s|$)",

    # Matches variations like "targeted at," "attacked against," "violations against," etc., capturing entities after these phrases.
    r"(?:targeted at|attacked against|violations against|operations against|breach of)\s((?:the\s)?[\w\s-]+?)(?:\.|,|\s|$)",

    # Matches entities targeted "against" specific attacks or operations
    r"against\s((?:the\s)?[\w\s-]+)\s(?:attacks|operations|violations|campaigns)",

    # Matches entities after "infiltrated."
    r"infiltrated\s((?:the\s)?[\w\s-]+?)(?:\.|,|\s|$)",

    # Matches entities after "breach of," "compromised," "exfiltration from," or "unauthorized access to."
    r"(?:breach of|compromised|exfiltration from|unauthorized access to)\s((?:the\s)?[\w\s-]+?)(?:\.|,|\s|$)",

    # Specifically matches cases where sensitive or classified information is targeted from an entity
    r"(?:targeting\s(?:sensitive|classified)\s(?:information|data)\sfrom)\s((?:the\s)?[\w\s-]+?)(?:\.|,|\s|$)"

    ]
    for pattern in regex_patterns:
        regex_matches = re.findall(pattern, text, re.IGNORECASE)
        targeted_entities.extend(regex_matches)

    # Use Named Entity Recognition (NER) for organizations and GPEs (Geopolitical Entities)
    for ent in doc.ents:
        if ent.label_ in ("ORG", "GPE"): #Extract organization and locations
            targeted_entities.append(ent.text)

    # Remove duplicates and return
    targeted_entities = list(set(targeted_entities))
    return targeted_entities if targeted_entities else ["Unknown"]



# Execution block
if __name__ == "__main__":
    path_input = get_pdf_path_or_folder("Enter PDF file path or folder path: ")

    if path_input:
        extract_threat_info_from_path(path_input)
    else:
        print("Invalid input. Exiting.")

