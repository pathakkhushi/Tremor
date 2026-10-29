"""
Tremor — Flask REST API
========================
Detects the small signals of failed logins before a breach happens.

Run:
    python server.py
Then open:
    frontend/index.html  in your browser.

Endpoints:
    GET  /api/health
    POST /api/analyze           body: { log_text, log_type?, threshold?, window_seconds? }
    GET  /api/sample/<type>     type: ssh | apache   ?threshold=5&window_seconds=60
    GET  /api/sample/<type>/raw returns raw text of the bundled sample log
"""

import os
import traceback

from flask import Flask, request, jsonify
from flask_cors import CORS

from analyzer import analyze

app = Flask(__name__)
CORS(app)   # Allow cross-origin requests from the frontend

SCRIPT_DIR      = os.path.dirname(os.path.abspath(__file__))
SAMPLE_LOGS_DIR = os.path.join(SCRIPT_DIR, 'sample_logs')
SAMPLE_FILES    = {
    'ssh':    'ssh_auth.log',
    'apache': 'apache_access.log',
}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _int_param(data: dict, key: str, default: int, min_val: int) -> int:
    try:
        return max(min_val, int(data.get(key, default)))
    except (TypeError, ValueError):
        return default


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    """Liveness check — confirm the API is reachable."""
    return jsonify({'status': 'ok', 'message': 'Tremor API is running OK'})


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    Analyse user-supplied log text.

    Request JSON:
        log_text       (str)  – raw log content
        log_type       (str)  – 'auto' | 'ssh' | 'apache'  (default: 'auto')
        threshold      (int)  – failed logins to flag       (default: 5)
        window_seconds (int)  – sliding window size (s)     (default: 60)
    """
    try:
        data           = request.get_json(force=True, silent=True) or {}
        log_text       = (data.get('log_text') or '').strip()
        log_type       = data.get('log_type', 'auto')
        threshold      = _int_param(data, 'threshold',      5,  1)
        window_seconds = _int_param(data, 'window_seconds', 60, 10)

        if not log_text:
            return jsonify({'error': 'No log text provided. Please paste log content.'}), 400

        result = analyze(log_text, log_type=log_type,
                         threshold=threshold, window_secs=window_seconds)
        return jsonify(result)

    except Exception as exc:
        traceback.print_exc()
        return jsonify({'error': f'Analysis failed: {exc}'}), 500


@app.route('/api/sample/<log_type>', methods=['GET'])
def api_sample(log_type):
    """Run analysis on the bundled sample log and return results."""
    try:
        if log_type not in SAMPLE_FILES:
            return jsonify({'error': f'Unknown log type "{log_type}". Use "ssh" or "apache".'}), 400

        threshold      = _int_param(request.args, 'threshold',      5,  1)
        window_seconds = _int_param(request.args, 'window_seconds', 60, 10)

        log_path = os.path.join(SAMPLE_LOGS_DIR, SAMPLE_FILES[log_type])
        with open(log_path, 'r') as f:
            log_text = f.read()

        result = analyze(log_text, log_type=log_type,
                         threshold=threshold, window_secs=window_seconds)
        return jsonify(result)

    except FileNotFoundError:
        return jsonify({'error': f'Sample log file not found for type "{log_type}".'}), 404
    except Exception as exc:
        traceback.print_exc()
        return jsonify({'error': str(exc)}), 500


@app.route('/api/sample/<log_type>/raw', methods=['GET'])
def api_sample_raw(log_type):
    """Return the raw text of a bundled sample log file."""
    try:
        if log_type not in SAMPLE_FILES:
            return jsonify({'error': 'Unknown log type'}), 400

        log_path = os.path.join(SAMPLE_LOGS_DIR, SAMPLE_FILES[log_type])
        with open(log_path, 'r') as f:
            content = f.read()

        return content, 200, {
            'Content-Type':                'text/plain; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
        }
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    banner = '=' * 55
    print(f'\n{banner}')
    print('  [*] BruteShield -- Log Analyzer API')
    print(banner)
    print('  URL  : http://localhost:5000')
    print('  UI   : open  frontend/index.html  in your browser')
    print(f'{banner}\n')
    app.run(debug=True, host='0.0.0.0', port=5000)
