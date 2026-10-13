"""
Unit and Integration Tests for AI CISO Copilot API
"""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_copilot_chat_endpoint_basic():
    response = client.post("/api/copilot/chat", json={
        "prompt": "Provide a 3-bullet executive CISO security briefing for the CEO."
    })
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    assert len(data["response"]) > 50
    assert "Executive" in data["response"] or "Risk" in data["response"]

def test_copilot_chat_jira_ticket():
    response = client.post("/api/copilot/chat", json={
        "prompt": "Generate a Jira incident ticket for the top vulnerability."
    })
    assert response.status_code == 200
    data = response.json()
    assert "Jira" in data["response"] or "SEC-OPS" in data["response"]

def test_copilot_chat_dpdp_compliance():
    response = client.post("/api/copilot/chat", json={
        "prompt": "What is the penalty exposure under India DPDP Act 2023?"
    })
    assert response.status_code == 200
    data = response.json()
    assert "DPDP" in data["response"] or "Penalty" in data["response"]

def test_copilot_missing_prompt_rejected():
    response = client.post("/api/copilot/chat", json={"prompt": ""})
    assert response.status_code == 400
