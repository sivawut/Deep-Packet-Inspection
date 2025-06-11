from mitmproxy import http
import joblib
import re
import numpy as np
from urllib.parse import urlparse

# === Load pre-trained model ===
model = joblib.load("url_model.pkl")  # Ensure this file is in your script's directory

# === Feature extraction functions ===
def is_base64(s):
    return bool(re.fullmatch(r'[A-Za-z0-9+/=]{16,}', s))

def is_hex(s):
    return bool(re.fullmatch(r'(?:[0-9a-fA-F]{2}){8,}', s))

def shannon_entropy(s):
    if not s:
        return 0
    probs = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * np.log2(p) for p in probs])

def extract_features(url):
    parsed = urlparse(url)
    path = parsed.path
    query = parsed.query
    return [
        int(any(is_base64(part) for part in path.split('/') + query.split('&'))),
        int(any(is_hex(part) for part in path.split('/') + query.split('&'))),
        path.count('/'),
        int('/../' in path),
        int('/./' in path),
        int(any(path.endswith(ext) for ext in ['.sh', '.tar.gz', '.exe', '.ps1'])),
        shannon_entropy(query),
        int(any(part != part.lower() and part != part.upper() for part in path.split('/')))
    ]

# === Intercept requests ===
def request(flow: http.HTTPFlow) -> None:
    url = flow.request.path
    features = extract_features(url)
    prediction = model.predict([features])[0]
    proba = model.predict_proba([features])[0][1]

    if prediction == 1 and proba > 0.8:
        # Block the request
        html = f"""
        <html>
            <head><title>Request Blocked</title></head>
            <body>
                <h1><font color='FF0000'>⚠️ Malicious Request Blocked by Machine Learning</font></h1>
                <p>The requested URL <b>{flow.request.pretty_url}</b> was flagged as suspicious.</p>
                <p>Probability: {proba:.2f}</p>
            </body>
        </html>
        """
        flow.response = http.Response.make(
            403,  # Forbidden
            html,
            {"Content-Type": "text/html"}
        )
    else:
        # Allow clean requests through silently
        pass
