import pytest
import demistomock as demisto
from unittest.mock import patch, MagicMock


def test_detect_indicator_type_ip():
    from ThreatKiller import detect_indicator_type
    assert detect_indicator_type("8.8.8.8") == "IP"


def test_detect_indicator_type_url():
    from ThreatKiller import detect_indicator_type
    assert detect_indicator_type("https://malicious.com") == "URL"


def test_detect_indicator_type_domain():
    from ThreatKiller import detect_indicator_type
    assert detect_indicator_type("malicious.com") == "Domain"


def test_detect_indicator_type_md5():
    from ThreatKiller import detect_indicator_type
    assert detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "File"


def test_detect_indicator_type_sha256():
    from ThreatKiller import detect_indicator_type
    assert detect_indicator_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "File"


def test_detect_indicator_type_cve():
    from ThreatKiller import detect_indicator_type
    assert detect_indicator_type("CVE-2021-44228") == "CVE"


def test_detect_indicator_type_email():
    from ThreatKiller import detect_indicator_type
    assert detect_indicator_type("test@malicious.com") == "Email"


def test_parse_indicators_list():
    from ThreatKiller import parse_indicators
    raw = [
        {"value": "8.8.8.8", "type": "ip", "score": 80, "tags": ["malicious"]},
        {"value": "malicious.com", "type": "domain", "score": 30, "tags": []},
    ]
    result = parse_indicators(raw, "value", "type")
    assert len(result) == 2
    assert result[0]["value"] == "8.8.8.8"
    assert result[0]["score"] == 3  # BAD
    assert result[1]["value"] == "malicious.com"
    assert result[1]["score"] == 1  # GOOD


def test_parse_indicators_dict():
    from ThreatKiller import parse_indicators
    raw = {
        "data": [
            {"value": "https://evil.com", "type": "url", "score": 50},
        ]
    }
    result = parse_indicators(raw, "value", "type")
    assert len(result) == 1
    assert result[0]["value"] == "https://evil.com"
    assert result[0]["score"] == 2  # SUSPICIOUS


def test_parse_indicators_empty():
    from ThreatKiller import parse_indicators
    result = parse_indicators([], "value", "type")
    assert result == []


def test_parse_indicators_missing_value():
    from ThreatKiller import parse_indicators
    raw = [{"type": "ip", "score": 50}]  # no value field
    result = parse_indicators(raw, "value", "type")
    assert result == []


def test_client_headers():
    from ThreatKiller import ThreatKillerClient
    client = ThreatKillerClient(
        base_url="https://api.example.com",
        token="test-token-123",
        verify=False,
        proxy=False,
    )
    assert client._headers["Authorization"] == "Bearer test-token-123"
    assert client._headers["Content-Type"] == "application/json"


def test_fetch_indicators_command():
    from ThreatKiller import fetch_indicators_command, ThreatKillerClient

    client = MagicMock(spec=ThreatKillerClient)
    client.get_indicators.return_value = [
        {"value": "8.8.8.8", "type": "ip", "score": 80},
        {"value": "malicious.com", "type": "domain", "score": 20},
    ]

    params = {
        "feed_endpoint": "/indicators",
        "value_field": "value",
        "type_field": "type",
        "max_indicators": "100",
    }

    result = fetch_indicators_command(client, params)
    assert len(result) == 2
    assert result[0]["value"] == "8.8.8.8"


def test_test_module_success():
    from ThreatKiller import test_module, ThreatKillerClient

    client = MagicMock(spec=ThreatKillerClient)
    client.get_indicators.return_value = [{"value": "8.8.8.8"}]

    result = test_module(client, {"feed_endpoint": "/indicators"})
    assert result == "ok"


def test_test_module_failure():
    from ThreatKiller import test_module, ThreatKillerClient

    client = MagicMock(spec=ThreatKillerClient)
    client.get_indicators.side_effect = Exception("Connection refused")

    result = test_module(client, {"feed_endpoint": "/indicators"})
    assert "Connection failed" in result