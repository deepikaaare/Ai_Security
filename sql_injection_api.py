from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from waitress import serve

app = Flask(__name__)
CORS(app)  # Allow Cross-Origin Resource Sharing

# Load the trained models and TF-IDF vectorizers for SQL injection and XSS detection
tfidf_vectorizer_sql = joblib.load("tfidf_vectorizer_sql.pkl")
model_sql = joblib.load("trained_model_sql.pkl")

tfidf_vectorizer_xss = joblib.load("tfidf_vectorizer_xss.pkl")
model_xss = joblib.load("trained_model_xss.pkl")

@app.route('/', methods=['POST'])
def detect_injections_api():
    username = request.json.get('username')
    password = request.json.get('password')

    # Vectorize input for SQL injection detection
    query_sql_username = tfidf_vectorizer_sql.transform([username.lower()])
    query_sql_password = tfidf_vectorizer_sql.transform([password.lower()])
    
    # Predict SQL injection for username and password
    prediction_sql_username = model_sql.predict(query_sql_username)
    prediction_sql_password = model_sql.predict(query_sql_password)

    # Predict XSS for username and password
    query_xss_username = tfidf_vectorizer_xss.transform([username.lower()])
    query_xss_password = tfidf_vectorizer_xss.transform([password.lower()])
    prediction_xss_username = model_xss.predict(query_xss_username)
    prediction_xss_password = model_xss.predict(query_xss_password)

    response = {
        "username_is_sql_injection": bool(prediction_sql_username),
        "password_is_sql_injection": bool(prediction_sql_password),
        "username_is_xss": bool(prediction_xss_username),
        "password_is_xss": bool(prediction_xss_password),
        "message": "No injection detected"
    }

    if response["username_is_sql_injection"] or response["password_is_sql_injection"]:
        response["message"] = "SQL Injection detected"
    elif response["username_is_xss"] or response["password_is_xss"]:
        response["message"] = "XSS detected"

    return jsonify(response)

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=4090)
