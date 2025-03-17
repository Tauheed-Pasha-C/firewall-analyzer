from flask import Flask, request, jsonify
import pandas as pd
import uuid
from firewall_logic import Policy, PolicyAnalyzer, auto_optimize_rules, to_dict, desc

app = Flask(__name__)

# In-memory storage for jobs (replace with database in production)
jobs = {}

@app.route('/submit-rules', methods=['POST'])
def submit_rules():
    """Endpoint to submit firewall rules via CSV or JSON"""
    job_id = str(uuid.uuid4())
    jobs[job_id] = {'status': 'received'}

    try:
        print("Request files:", request.files)  # Debug: Check if files are received
        if 'file' in request.files:
            # Handle CSV upload
            file = request.files['file']
            print("File received:", file.filename)  # Debug: Check the filename
            df = pd.read_csv(file)
            print("DataFrame created:", df.head())  # Debug: Check the DataFrame
            jobs[job_id]['original_rules'] = df.to_dict()
        elif request.json:
            # Handle JSON payload
            print("JSON payload received:", request.json)  # Debug: Check JSON payload
            df = pd.DataFrame(request.json)
            jobs[job_id]['original_rules'] = df.to_dict()
        else:
            print("No valid data provided")  # Debug: Log the error
            return jsonify({'error': 'No valid data provided'}), 400
        
        jobs[job_id]['status'] = 'submitted'
        return jsonify({'job_id': job_id, 'status': 'submitted'}), 202
    
    except Exception as e:
        print("Error:", str(e))  # Debug: Log the exception
        jobs[job_id]['status'] = 'error'
        return jsonify({'error': str(e)}), 400

@app.route('/analyze/<job_id>', methods=['POST'])
def analyze_rules(job_id):
    """Endpoint to trigger rule analysis"""
    if job_id not in jobs:
        return jsonify({'error': 'Invalid job ID'}), 404

    try:
        # Reconstruct DataFrame from stored data
        df = pd.DataFrame(jobs[job_id]['original_rules'])
        
        # Perform analysis
        policies = [Policy(**r) for r in df.to_dict('records')]
        analyzer = PolicyAnalyzer(policies)
        anom = analyzer.get_anomalies()
        anom_dict = to_dict(anom)
        
        # Store analysis results
        jobs[job_id]['analysis'] = {
            'anomalies': anom_dict,
            'metrics': {k: sum(1 for v in anom_dict.values() if k in v.values()) 
                        for k in desc.keys()}
        }
        
        # Perform optimization
        optimized_df = auto_optimize_rules(df, anom_dict)
        jobs[job_id]['optimized_rules'] = optimized_df.to_dict(orient='records')
        
        jobs[job_id]['status'] = 'completed'
        return jsonify({'status': 'analysis completed'}), 200
    
    except Exception as e:
        jobs[job_id]['status'] = 'error'
        return jsonify({'error': str(e)}), 500

@app.route('/results/<job_id>', methods=['GET'])
def get_results(job_id):
    """Retrieve analysis results"""
    if job_id not in jobs:
        return jsonify({'error': 'Invalid job ID'}), 404

    if jobs[job_id]['status'] != 'completed':
        return jsonify({'status': jobs[job_id]['status']}), 202

    try:
        # Prepare response data
        response = {
            'job_id': job_id,
            'status': 'completed',
            'analysis': jobs[job_id]['analysis'],
            'optimized_rules': jobs[job_id]['optimized_rules'],
            'original_rule_count': len(jobs[job_id]['original_rules']),
            'optimized_rule_count': len(jobs[job_id]['optimized_rules'])
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)