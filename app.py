from flask import Flask, request, jsonify, render_template
from script import analyze_url, calculate_risk

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "message": "Phishing URL Detector API is running"
    })


@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"]

    if not isinstance(url, str):
        return jsonify({"error": "URL must be a string"}), 400

    if not url.strip():
        return jsonify({"error": "URL cannot be empty"}), 400

    analysis = analyze_url(url)

    if "error" in analysis:
        return jsonify(analysis), 400

    risk = calculate_risk(analysis)

    return jsonify({
        "analysis": analysis,
        "risk_assessment": risk
    })


if __name__ == "__main__":
    app.run(debug=True)