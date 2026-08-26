import csv
import os
from datetime import datetime, timezone
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

CSV_FILE_PATH = os.path.join(os.path.dirname(__file__), 'threats.csv')

# Country pool for geo-distribution on 3D globe
COUNTRY_POOL = ["RU", "CN", "US", "DE", "NG", "CM", "BR", "IN", "IR", "KP", "FR", "GB"]

@app.route('/api/threats', methods=['GET'])
def get_threats():
    threats = []
    
    if not os.path.exists(CSV_FILE_PATH):
        return jsonify({"error": "threats.csv file not found"}), 404

    try:
        with open(CSV_FILE_PATH, mode='r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            
            idx = 0
            for row in reader:
                if not row or len(row) < 5 or row[0].startswith('#'):
                    continue
                
                timestamp = row[1] if len(row) > 1 else datetime.now(timezone.utc).isoformat()
                ioc_type = row[3] if len(row) > 3 else "IOC"
                threat_type = row[4] if len(row) > 4 else "Malware"
                malware_name = row[7] if len(row) > 7 and row[7] else "Unknown Threat"
                confidence = row[8] if len(row) > 8 and row[8].isdigit() else "50"
                
                # Format clean names
                clean_threat = threat_type.replace('_', ' ').replace('"', '').title()
                clean_name = malware_name.replace('"', '').title()
                
                # Assign country dynamically from pool
                assigned_country = COUNTRY_POOL[idx % len(COUNTRY_POOL)]

                threats.append({
                    "title": f"{clean_name} ({ioc_type.upper()})",
                    "attack_type": clean_threat if clean_threat else "Malware",
                    "country": assigned_country,
                    "ioc_count": int(confidence),
                    "created": timestamp.replace('"', '')
                })
                idx += 1

    except Exception as e:
        print(f"Error reading CSV: {e}")
        return jsonify({"error": str(e)}), 500

    return jsonify(threats[:60])

if __name__ == '__main__':
    app.run(debug=True, port=5000)
