import demistomock as demisto
from CommonServerPython import *
from typing import Any

# ─── Constants ────────────────────────────────────────────────────────────────

INDICATOR_TYPE_MAP = {
    "ip": FeedIndicatorType.IP,
    "ipv4": FeedIndicatorType.IP,
    "ipv6": FeedIndicatorType.IPv6,
    "url": FeedIndicatorType.URL,
    "domain": FeedIndicatorType.Domain,
    "md5": FeedIndicatorType.File,
    "sha1": FeedIndicatorType.File,
    "sha256": FeedIndicatorType.File,
    "cve": FeedIndicatorType.CVE,
    "email": FeedIndicatorType.Email,
}


# ─── Client ───────────────────────────────────────────────────────────────────

class ThreatKillerClient(BaseClient):
    """Generic REST/JSON client with Bearer token auth."""

    def __init__(self, base_url: str, token: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url.rstrip("/"), verify=verify, proxy=proxy)
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def get_indicators(self, endpoint: str, params: dict | None = None) -> dict | list:
        """Pull indicators from the API."""
        return self._http_request(
            method="GET",
            url_suffix=endpoint,
            headers=self._headers,
            params=params or {},
        )

    def get_indicator_by_value(self, endpoint: str, value: str) -> dict | list:
        """Query a specific indicator by value."""
        return self._http_request(
            method="GET",
            url_suffix=f"{endpoint}/{value}",
            headers=self._headers,
        )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def detect_indicator_type(value: str, type_hint: str = "") -> str:
    """Auto-detect indicator type from value or hint."""
    if type_hint:
        return INDICATOR_TYPE_MAP.get(type_hint.lower(), FeedIndicatorType.IP)

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return FeedIndicatorType.IP
    elif re.match(r"^https?://", value):
        return FeedIndicatorType.URL
    elif re.match(r"^[a-fA-F0-9]{32}$", value):
        return FeedIndicatorType.File  # MD5
    elif re.match(r"^[a-fA-F0-9]{40}$", value):
        return FeedIndicatorType.File  # SHA1
    elif re.match(r"^[a-fA-F0-9]{64}$", value):
        return FeedIndicatorType.File  # SHA256
    elif re.match(r"^CVE-\d{4}-\d+$", value, re.IGNORECASE):
        return FeedIndicatorType.CVE
    elif re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
        return FeedIndicatorType.Email
    else:
        return FeedIndicatorType.Domain


def parse_indicators(raw_data: Any, value_field: str, type_field: str) -> list[dict]:
    """Parse raw API response into XSIAM indicator format."""
    indicators = []

    # Handle both list and dict responses
    if isinstance(raw_data, dict):
        items = raw_data.get("data") or raw_data.get("indicators") or raw_data.get("results") or [raw_data]
    elif isinstance(raw_data, list):
        items = raw_data
    else:
        return []

    for item in items:
        if not isinstance(item, dict):
            continue

        value = item.get(value_field, "")
        type_hint = item.get(type_field, "")

        if not value:
            continue

        indicator_type = detect_indicator_type(value, type_hint)
        score = item.get("score") or item.get("confidence") or item.get("risk_score") or 0

        # Map score to DBotScore
        if isinstance(score, (int, float)):
            if score >= 75:
                dbot_score = Common.DBotScore.BAD
            elif score >= 40:
                dbot_score = Common.DBotScore.SUSPICIOUS
            else:
                dbot_score = Common.DBotScore.GOOD
        else:
            dbot_score = Common.DBotScore.NONE

        indicators.append({
            "value": value,
            "type": indicator_type,
            "rawJSON": item,
            "score": dbot_score,
            "fields": {
                "tags": item.get("tags", []),
                "description": item.get("description", ""),
                "firstseenbysource": item.get("first_seen") or item.get("created_at", ""),
                "lastseenbysource": item.get("last_seen") or item.get("updated_at", ""),
                "confidence": score,
                "trafficlightprotocol": item.get("tlp", "WHITE"),
            },
        })

    return indicators


# ─── Feed Command (Scheduled Auto-Pull) ───────────────────────────────────────

def fetch_indicators_command(client: ThreatKillerClient, params: dict) -> list[dict]:
    """Called automatically by XSIAM on a schedule to pull indicators."""
    endpoint = params.get("feed_endpoint", "/indicators")
    value_field = params.get("value_field", "value")
    type_field = params.get("type_field", "type")
    limit = int(params.get("max_indicators", 1000))

    raw = client.get_indicators(endpoint, params={"limit": limit})
    indicators = parse_indicators(raw, value_field, type_field)
    return indicators


# ─── Manual Commands ──────────────────────────────────────────────────────────

def get_indicators_command(client: ThreatKillerClient, args: dict, params: dict) -> CommandResults:
    """Manual command to pull and display indicators."""
    endpoint = params.get("feed_endpoint", "/indicators")
    value_field = params.get("value_field", "value")
    type_field = params.get("type_field", "type")
    limit = int(args.get("limit", 50))

    raw = client.get_indicators(endpoint, params={"limit": limit})
    indicators = parse_indicators(raw, value_field, type_field)

    readable = tableToMarkdown(
        "ThreatKiller Indicators",
        [{"Value": i["value"], "Type": i["type"], "Score": i["score"], "Tags": i["fields"]["tags"]} for i in indicators],
        headers=["Value", "Type", "Score", "Tags"],
    )

    return CommandResults(
        outputs_prefix="ThreatKiller.Indicators",
        outputs_key_field="value",
        outputs=indicators,
        readable_output=readable,
    )


def ip_command(client: ThreatKillerClient, args: dict, params: dict) -> list[CommandResults]:
    endpoint = params.get("feed_endpoint", "/indicators")
    value_field = params.get("value_field", "value")
    type_field = params.get("type_field", "type")
    ips = argToList(args.get("ip"))
    results = []

    for ip in ips:
        try:
            raw = client.get_indicator_by_value(endpoint, ip)
            indicators = parse_indicators(raw, value_field, type_field)
            data = indicators[0] if indicators else {}
            score = data.get("score", Common.DBotScore.NONE)
        except Exception:
            data = {}
            score = Common.DBotScore.NONE

        dbot = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name="ThreatKiller",
            score=score,
        )
        results.append(CommandResults(
            outputs_prefix="ThreatKiller.IP",
            outputs_key_field="value",
            outputs=data.get("rawJSON", {"value": ip}),
            readable_output=tableToMarkdown(f"IP: {ip}", data.get("rawJSON", {"value": ip, "result": "No data found"})),
            indicator=Common.IP(ip=ip, dbot_score=dbot),
        ))
    return results


def url_command(client: ThreatKillerClient, args: dict, params: dict) -> list[CommandResults]:
    endpoint = params.get("feed_endpoint", "/indicators")
    value_field = params.get("value_field", "value")
    type_field = params.get("type_field", "type")
    urls = argToList(args.get("url"))
    results = []

    for url in urls:
        try:
            raw = client.get_indicator_by_value(endpoint, url)
            indicators = parse_indicators(raw, value_field, type_field)
            data = indicators[0] if indicators else {}
            score = data.get("score", Common.DBotScore.NONE)
        except Exception:
            data = {}
            score = Common.DBotScore.NONE

        dbot = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name="ThreatKiller",
            score=score,
        )
        results.append(CommandResults(
            outputs_prefix="ThreatKiller.URL",
            outputs_key_field="value",
            outputs=data.get("rawJSON", {"value": url}),
            readable_output=tableToMarkdown(f"URL: {url}", data.get("rawJSON", {"value": url, "result": "No data found"})),
            indicator=Common.URL(url=url, dbot_score=dbot),
        ))
    return results


def domain_command(client: ThreatKillerClient, args: dict, params: dict) -> list[CommandResults]:
    endpoint = params.get("feed_endpoint", "/indicators")
    value_field = params.get("value_field", "value")
    type_field = params.get("type_field", "type")
    domains = argToList(args.get("domain"))
    results = []

    for domain in domains:
        try:
            raw = client.get_indicator_by_value(endpoint, domain)
            indicators = parse_indicators(raw, value_field, type_field)
            data = indicators[0] if indicators else {}
            score = data.get("score", Common.DBotScore.NONE)
        except Exception:
            data = {}
            score = Common.DBotScore.NONE

        dbot = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name="ThreatKiller",
            score=score,
        )
        results.append(CommandResults(
            outputs_prefix="ThreatKiller.Domain",
            outputs_key_field="value",
            outputs=data.get("rawJSON", {"value": domain}),
            readable_output=tableToMarkdown(f"Domain: {domain}", data.get("rawJSON", {"value": domain, "result": "No data found"})),
            indicator=Common.Domain(domain=domain, dbot_score=dbot),
        ))
    return results


def file_command(client: ThreatKillerClient, args: dict, params: dict) -> list[CommandResults]:
    endpoint = params.get("feed_endpoint", "/indicators")
    value_field = params.get("value_field", "value")
    type_field = params.get("type_field", "type")
    hashes = argToList(args.get("file"))
    results = []

    for file_hash in hashes:
        try:
            raw = client.get_indicator_by_value(endpoint, file_hash)
            indicators = parse_indicators(raw, value_field, type_field)
            data = indicators[0] if indicators else {}
            score = data.get("score", Common.DBotScore.NONE)
        except Exception:
            data = {}
            score = Common.DBotScore.NONE

        dbot = Common.DBotScore(
            indicator=file_hash,
            indicator_type=DBotScoreType.FILE,
            integration_name="ThreatKiller",
            score=score,
        )
        results.append(CommandResults(
            outputs_prefix="ThreatKiller.File",
            outputs_key_field="value",
            outputs=data.get("rawJSON", {"value": file_hash}),
            readable_output=tableToMarkdown(f"File Hash: {file_hash}", data.get("rawJSON", {"value": file_hash, "result": "No data found"})),
            indicator=Common.File(dbot_score=dbot),
        ))
    return results


def cve_command(client: ThreatKillerClient, args: dict, params: dict) -> list[CommandResults]:
    endpoint = params.get("feed_endpoint", "/indicators")
    value_field = params.get("value_field", "value")
    type_field = params.get("type_field", "type")
    cves = argToList(args.get("cve"))
    results = []

    for cve in cves:
        try:
            raw = client.get_indicator_by_value(endpoint, cve)
            indicators = parse_indicators(raw, value_field, type_field)
            data = indicators[0] if indicators else {}
        except Exception:
            data = {}

        results.append(CommandResults(
            outputs_prefix="ThreatKiller.CVE",
            outputs_key_field="value",
            outputs=data.get("rawJSON", {"value": cve}),
            readable_output=tableToMarkdown(f"CVE: {cve}", data.get("rawJSON", {"value": cve, "result": "No data found"})),
        ))
    return results


def email_command(client: ThreatKillerClient, args: dict, params: dict) -> list[CommandResults]:
    endpoint = params.get("feed_endpoint", "/indicators")
    value_field = params.get("value_field", "value")
    type_field = params.get("type_field", "type")
    emails = argToList(args.get("email"))
    results = []

    for email in emails:
        try:
            raw = client.get_indicator_by_value(endpoint, email)
            indicators = parse_indicators(raw, value_field, type_field)
            data = indicators[0] if indicators else {}
            score = data.get("score", Common.DBotScore.NONE)
        except Exception:
            data = {}
            score = Common.DBotScore.NONE

        dbot = Common.DBotScore(
            indicator=email,
            indicator_type=DBotScoreType.EMAIL,
            integration_name="ThreatKiller",
            score=score,
        )
        results.append(CommandResults(
            outputs_prefix="ThreatKiller.Email",
            outputs_key_field="value",
            outputs=data.get("rawJSON", {"value": email}),
            readable_output=tableToMarkdown(f"Email: {email}", data.get("rawJSON", {"value": email, "result": "No data found"})),
            indicator=Common.EMAIL(address=email, dbot_score=dbot),
        ))
    return results


# ─── Test Module ──────────────────────────────────────────────────────────────

def test_module(client: ThreatKillerClient, params: dict) -> str:
    """Test connectivity to the API."""
    try:
        endpoint = params.get("feed_endpoint", "/indicators")
        client.get_indicators(endpoint, params={"limit": 1})
        return "ok"
    except Exception as e:
        return f"Connection failed: {e}"


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("base_url", "").rstrip("/")
    token = params.get("credentials", {}).get("password") or params.get("token", "")
    verify_ssl = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    client = ThreatKillerClient(
        base_url=base_url,
        token=token,
        verify=verify_ssl,
        proxy=proxy,
    )

    try:
        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params)
            for batch in batch(indicators, batch_size=2000):
                demisto.createIndicators(batch)
        elif command == "threatkiller-get-indicators":
            return_results(get_indicators_command(client, args, params))
        elif command == "ip":
            return_results(ip_command(client, args, params))
        elif command == "url":
            return_results(url_command(client, args, params))
        elif command == "domain":
            return_results(domain_command(client, args, params))
        elif command == "file":
            return_results(file_command(client, args, params))
        elif command == "cve":
            return_results(cve_command(client, args, params))
        elif command == "email":
            return_results(email_command(client, args, params))
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command}. Error: {e}")


if __name__ == "__main__":
    main()