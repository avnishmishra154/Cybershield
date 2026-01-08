from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import hashlib
import random
import time
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Mock threat database
THREAT_DATABASE = {
    "trojan": ["Generic.Trojan", "Banker.Trojan", "Backdoor.Trojan"],
    "ransomware": ["WannaCry", "Ryuk", "LockBit"],
    "adware": ["PopUnder", "BrowserHijacker", "Adware.Generic"],
    "virus": ["Nimda", "Sasser", "Mydoom"],
    "worm": ["Conficker", "Stuxnet", "Morris"]
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    try:
        # Simulate file processing
        time.sleep(random.uniform(0.5, 2.0))
        
        # Generate random result
        is_malicious = random.random() > 0.7
        
        result = {
            "status": "success",
            "is_malicious": is_malicious,
            "filename": request.json.get('filename', 'unknown'),
            "size": request.json.get('size', 0),
            "scan_date": datetime.now().isoformat()
        }
        
        if is_malicious:
            threat_type = random.choice(list(THREAT_DATABASE.keys()))
            threat_name = random.choice(THREAT_DATABASE[threat_type])
            result.update({
                "threat_name": threat_name,
                "threat_type": threat_type,
                "severity": random.choice(["low", "medium", "high", "critical"]),
                "description": f"This file contains {threat_name} {threat_type}",
                "confidence": round(random.uniform(0.7, 1.0), 2)
            })
        else:
            result.update({
                "threat_name": None,
                "confidence": round(random.uniform(0.9, 1.0), 2)
            })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    try:
        url = request.json.get('url', '').strip()
        
        if not url:
            return jsonify({
                "status": "error",
                "message": "No URL provided"
            }), 400
        
        # Simulate scanning delay
        time.sleep(random.uniform(0.3, 1.5))
        
        # Check if URL looks suspicious (mock logic)
        suspicious_keywords = ['malware', 'virus', 'trojan', 'hack', 'crack', 'keygen']
        is_suspicious = any(keyword in url.lower() for keyword in suspicious_keywords)
        
        # Generate random result
        is_malicious = is_suspicious or random.random() > 0.8
        
        result = {
            "status": "success",
            "url": url,
            "is_malicious": is_malicious,
            "scan_date": datetime.now().isoformat(),
            "reputation_score": random.randint(0, 100)
        }
        
        if is_malicious:
            threat_type = random.choice(["phishing", "malware", "scam", "suspicious"])
            result.update({
                "threat_type": threat_type,
                "threat_level": random.choice(["warning", "danger", "critical"]),
                "description": f"This URL has been flagged as {threat_type}",
                "recommendation": "Do not visit this website"
            })
        else:
            result.update({
                "description": "This URL appears to be safe",
                "recommendation": "Proceed with normal caution"
            })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/scan/hash', methods=['POST'])
def scan_hash():
    try:
        hash_value = request.json.get('hash', '').strip()
        hash_type = request.json.get('type', 'md5').lower()
        
        if not hash_value:
            return jsonify({
                "status": "error",
                "message": "No hash provided"
            }), 400
        
        # Simulate hash database lookup
        time.sleep(random.uniform(0.2, 1.0))
        
        # Mock known malicious hashes
        malicious_hashes = [
            "098f6bcd4621d373cade4e832627b4f6",
            "5d41402abc4b2a76b9719d911017c592",
            "7d793037a0760186574b0282f2f435e7"
        ]
        
        is_known_threat = hash_value in malicious_hashes or random.random() > 0.9
        
        result = {
            "status": "success",
            "hash": hash_value,
            "hash_type": hash_type,
            "is_known_threat": is_known_threat,
            "scan_date": datetime.now().isoformat(),
            "database_matches": random.randint(0, 85)
        }
        
        if is_known_threat:
            threat = random.choice(list(THREAT_DATABASE.values()))[0]
            result.update({
                "threat_name": threat,
                "first_seen": "2023-01-15",
                "detection_count": random.randint(100, 10000),
                "description": f"This hash matches known {threat} malware"
            })
        else:
            result.update({
                "description": "No matches found in threat database",
                "first_seen": None,
                "detection_count": 0
            })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify({
        "status": "success",
        "stats": {
            "total_scans": random.randint(1000, 10000),
            "threats_detected": random.randint(100, 1000),
            "detection_rate": round(random.uniform(0.95, 0.999), 3),
            "avg_scan_time": round(random.uniform(0.5, 2.0), 2),
            "active_threats": random.randint(10, 100)
        },
        "threat_distribution": {
            "trojan": random.randint(100, 500),
            "ransomware": random.randint(50, 200),
            "adware": random.randint(200, 800),
            "virus": random.randint(30, 150),
            "worm": random.randint(20, 100)
        }
    })

if __name__ == '__main__':
    app.run(debug=True, port=5001)