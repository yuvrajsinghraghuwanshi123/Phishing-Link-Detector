from app import app
import database


def test_home_page():
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200


def test_health_endpoint():
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json["status"] == "healthy"

def test_analyze_valid_url():
    client = app.test_client()

    response = client.post(
        "/analyze",
        json={"url": "https://google.com"}
    )

    assert response.status_code == 200
    assert "analysis" in response.json
    assert "risk_assessment" in response.json


def test_analyze_missing_url():
    client = app.test_client()

    response = client.post("/analyze", json={})

    assert response.status_code == 400
    assert response.json["error"] == "URL is required"

def test_analyze_empty_url():
    client = app.test_client()

    response = client.post(
        "/analyze",
        json={"url": ""}
    )

    assert response.status_code == 400
    assert response.json["error"] == "URL cannot be empty"


def test_analyze_non_string_url():
    client = app.test_client()

    response = client.post(
        "/analyze",
        json={"url": 123}
    )

    assert response.status_code == 400
    assert response.json["error"] == "URL must be a string"

def test_history_endpoint():
    client = app.test_client()

    response = client.get("/history")

    assert response.status_code == 200
    assert isinstance(response.json, list)

def test_database_persistence(tmp_path, monkeypatch):
    test_db = tmp_path / "test_history.db"

    monkeypatch.setattr(database, "DB_PATH", test_db)

    database.init_db()

    analysis = {
        "url": "https://google.com",
        "hostname": "google.com"
    }

    risk = {
        "score": 0,
        "level": "Low",
        "reasons": []
    }

    scan_id = database.save_scan(analysis, risk)

    history = database.get_scan_history()

    assert scan_id == 1
    assert len(history) == 1
    assert history[0]["url"] == "https://google.com"
    assert history[0]["risk_score"] == 0
    assert history[0]["risk_level"] == "Low"

def test_analyze_saves_scan_to_database(tmp_path, monkeypatch):
    test_db = tmp_path / "test_history.db"

    monkeypatch.setattr(database, "DB_PATH", test_db)

    database.init_db()

    client = app.test_client()

    response = client.post(
        "/analyze",
        json={"url": "https://google.com"}
    )

    assert response.status_code == 200

    history = database.get_scan_history()

    assert len(history) == 1
    assert history[0]["url"] == "https://google.com"