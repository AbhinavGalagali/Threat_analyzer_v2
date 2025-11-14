from flask import Flask, render_template, request, send_file, abort
from pathlib import Path
import json
from werkzeug.utils import secure_filename
from threat_analyzer import extract_threat_info_from_path
import os

app = Flask(__name__)
UPLOAD_FOLDER = Path(__file__).parent / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True, parents=True)

CATEGORIES = [
    'IoCs', 'TTPs', 'Malware', 'Threat Actors', 'Targeted Entities'
]

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        files = request.files.getlist("pdf_files")
        selected_categories = request.form.getlist('categories')
        all_reports = []

        for file in files:
            if file and file.filename.endswith('.pdf'):
                try:
                    filename = secure_filename(file.filename)
                    file_path = UPLOAD_FOLDER / filename
                    file.save(file_path)

                    output_filename = f"output_{Path(filename).stem}.json"
                    output_path = UPLOAD_FOLDER / output_filename

                    extract_threat_info_from_path(file_path)

                    if output_path.exists():
                        with open(output_path, "r", encoding="utf-8") as f:
                            threat_data = json.load(f)

                        metadata_keys = {'original_filename', 'report_filename', 'timestamp', 'report_id'}
                        metadata = {k: threat_data[k] for k in metadata_keys if k in threat_data}
                        data_categories = {k: v for k, v in threat_data.items() if k not in metadata_keys}
                        
                        if selected_categories:
                            filtered_data = {k: v for k, v in data_categories.items() if k in selected_categories}
                        else:
                            filtered_data = data_categories

                        filtered_data.update(metadata)
                        all_reports.append(filtered_data)
                    else:
                        app.logger.error(f"JSON output not found for {filename}")
                        continue

                except Exception as e:
                    app.logger.error(f"Error processing {file.filename}: {str(e)}")
                    continue

        return render_template("index.html", 
                             threat_data=all_reports,
                             categories=CATEGORIES,
                             selected_categories=selected_categories)
    
    return render_template("index.html", 
                         threat_data=None,
                         categories=CATEGORIES,
                         selected_categories=CATEGORIES)

@app.route("/download/<filename>")
def download(filename):
    try:
        safe_name = secure_filename(filename)
        file_path = UPLOAD_FOLDER / safe_name
        
        if not file_path.exists():
            abort(404, description="Report not found")
            
        return send_file(
            str(file_path.absolute()),
            as_attachment=True,
            download_name=safe_name,
            mimetype='application/json'
        )
        
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        abort(500, description="File download failed")

if __name__ == "__main__":
    app.run(debug=True)