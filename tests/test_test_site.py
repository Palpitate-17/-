from fastapi.testclient import TestClient

from test_site.app import app


client = TestClient(app)


def test_site_health_and_index():
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/").status_code == 200


def test_secure_route_has_required_headers():
    response = client.get("/weak/secure")
    assert response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_cookie_positive_and_negative_pages():
    insecure = client.get("/weak/insecure-cookie").headers["set-cookie"].lower()
    secure = client.get("/weak/secure-cookie").headers["set-cookie"].lower()
    assert "httponly" not in insecure and "secure" not in insecure
    assert "httponly" in secure and "secure" in secure and "samesite=strict" in secure
