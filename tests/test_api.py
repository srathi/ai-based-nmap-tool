import pytest
from unittest.mock import patch


class TestAuth:
    def test_health_endpoint(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_login_success(self, client, test_user):
        response = client.post("/api/v1/auth/login", json={
            "username": "testuser",
            "password": "testpass123",
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_failure(self, client):
        response = client.post("/api/v1/auth/login", json={
            "username": "nonexistent",
            "password": "wrongpass",
        })
        assert response.status_code == 401
        assert "Invalid" in response.json()["detail"]

    def test_login_wrong_password(self, client, test_user):
        response = client.post("/api/v1/auth/login", json={
            "username": "testuser",
            "password": "wrongpass",
        })
        assert response.status_code == 401

    def test_register_user(self, client, admin_auth_headers):
        response = client.post(
            "/api/v1/auth/register",
            json={"username": "newuser", "password": "newpass123", "email": "new@example.com", "role": "viewer"},
            headers=admin_auth_headers,
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_register_duplicate(self, client, admin_auth_headers, test_user):
        response = client.post(
            "/api/v1/auth/register",
            json={"username": "testuser", "password": "testpass123"},
            headers=admin_auth_headers,
        )
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

    def test_register_unauthorized(self, client, auth_headers):
        response = client.post(
            "/api/v1/auth/register",
            json={"username": "hacker", "password": "pass"},
            headers=auth_headers,
        )
        assert response.status_code == 403

    def test_me_endpoint(self, client, auth_headers):
        response = client.get("/api/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["username"] == "testuser"

    def test_unauthorized_access(self, client):
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401
        response = client.get("/api/v1/targets")
        assert response.status_code == 401
        response = client.get("/api/v1/scans")
        assert response.status_code == 401


class TestTargets:
    def test_get_targets_empty(self, client, auth_headers):
        response = client.get("/api/v1/targets", headers=auth_headers)
        assert response.status_code == 200
        assert response.json() == []

    def test_create_target(self, client, auth_headers):
        response = client.post(
            "/api/v1/targets",
            json={"name": "test-target", "target_value": "192.168.1.1", "target_type": "ip"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test-target"
        assert data["target_value"] == "192.168.1.1"
        assert "id" in data

    def test_get_targets(self, client, auth_headers):
        client.post("/api/v1/targets", json={"name": "t1", "target_value": "10.0.0.1"}, headers=auth_headers)
        client.post("/api/v1/targets", json={"name": "t2", "target_value": "10.0.0.2"}, headers=auth_headers)
        response = client.get("/api/v1/targets", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_delete_target(self, client, auth_headers):
        resp = client.post("/api/v1/targets", json={"name": "del-target", "target_value": "10.0.0.1"}, headers=auth_headers)
        target_id = resp.json()["id"]
        response = client.delete(f"/api/v1/targets/{target_id}", headers=auth_headers)
        assert response.status_code == 200
        response = client.delete(f"/api/v1/targets/99999", headers=auth_headers)
        assert response.status_code == 404


class TestScans:
    def test_launch_scan(self, client, auth_headers):
        resp = client.post("/api/v1/targets", json={"name": "scan-target", "target_value": "10.0.0.1"}, headers=auth_headers)
        target_id = resp.json()["id"]
        response = client.post(
            "/api/v1/scans",
            json={"name": "test-scan", "target_id": target_id, "profile_id": 1},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test-scan"
        assert data["status"] == "running"

    def test_get_scans(self, client, auth_headers):
        resp = client.post("/api/v1/targets", json={"name": "t", "target_value": "10.0.0.1"}, headers=auth_headers)
        tid = resp.json()["id"]
        client.post("/api/v1/scans", json={"name": "s1", "target_id": tid, "profile_id": 1}, headers=auth_headers)
        response = client.get("/api/v1/scans", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1

    def test_cancel_scan(self, client, auth_headers):
        resp = client.post("/api/v1/targets", json={"name": "t", "target_value": "10.0.0.1"}, headers=auth_headers)
        tid = resp.json()["id"]
        resp2 = client.post("/api/v1/scans", json={"name": "cancel-scan", "target_id": tid, "profile_id": 1}, headers=auth_headers)
        scan_id = resp2.json()["id"]
        response = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=auth_headers)
        assert response.status_code == 200

    def test_cancel_nonexistent_scan(self, client, auth_headers):
        response = client.post("/api/v1/scans/99999/cancel", headers=auth_headers)
        assert response.status_code == 404


class TestResults:
    def test_get_scan_results_empty(self, client, auth_headers):
        response = client.get("/api/v1/scans/1/results", headers=auth_headers)
        assert response.status_code == 200

    def test_get_scan_results(self, client, auth_headers, test_db):
        from tests.conftest import ScanJob, ScanResult, Target
        import json
        target = Target(name="t", target_value="10.0.0.1")
        test_db.add(target)
        test_db.commit()
        job = ScanJob(name="r-scan", target_id=target.id, profile_id=1, created_by=1, status="completed")
        test_db.add(job)
        test_db.commit()
        scan_data = {"hosts": [{"ip": "10.0.0.1", "status": "up", "ports": [{"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh"}]}]}
        result = ScanResult(scan_job_id=job.id, normalized_data=json.dumps(scan_data))
        test_db.add(result)
        test_db.commit()
        response = client.get(f"/api/v1/scans/{job.id}/results", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["host_count"] == 1
        assert data["hosts"][0]["ip"] == "10.0.0.1"

    def test_export_json(self, client, auth_headers, test_db):
        from tests.conftest import ScanJob, ScanResult, Target
        import json
        target = Target(name="t", target_value="10.0.0.1")
        test_db.add(target)
        test_db.commit()
        job = ScanJob(name="export-json", target_id=target.id, profile_id=1, created_by=1, status="completed")
        test_db.add(job)
        test_db.commit()
        scan_data = {"hosts": [{"ip": "10.0.0.1", "ports": []}]}
        result = ScanResult(scan_job_id=job.id, normalized_data=json.dumps(scan_data))
        test_db.add(result)
        test_db.commit()
        response = client.get(f"/api/v1/scans/{job.id}/export/json", headers=auth_headers)
        assert response.status_code == 200

    def test_export_csv(self, client, auth_headers, test_db):
        from tests.conftest import ScanJob, ScanResult, Target
        import json
        target = Target(name="t", target_value="10.0.0.1")
        test_db.add(target)
        test_db.commit()
        job = ScanJob(name="export-csv", target_id=target.id, profile_id=1, created_by=1, status="completed")
        test_db.add(job)
        test_db.commit()
        scan_data = {"hosts": [{"ip": "10.0.0.1", "ports": [{"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh"}]}]}
        result = ScanResult(scan_job_id=job.id, normalized_data=json.dumps(scan_data))
        test_db.add(result)
        test_db.commit()
        response = client.get(f"/api/v1/scans/{job.id}/export/csv", headers=auth_headers)
        assert response.status_code == 200
        assert "text/csv" in response.headers.get("content-type", "")


class TestRateLimiting:
    def test_rate_limiting(self, client, auth_headers):
        for _ in range(5):
            response = client.get("/api/v1/health", headers=auth_headers)
            assert response.status_code == 200
