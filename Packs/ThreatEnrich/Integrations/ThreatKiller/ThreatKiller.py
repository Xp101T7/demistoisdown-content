import demistomock as demisto
from CommonServerPython import *

# ─── GraphQL Queries ──────────────────────────────────────────────────────────

IP_QUERY = """
query($value: String!) {
  stixCyberObservables(filters: {
    mode: and,
    filters: [{key: "value", values: [$value]}],
    filterGroups: []
  }) {
    edges {
      node {
        id
        entity_type
        ... on IPv4Addr { value }
        ... on IPv6Addr { value }
        indicators { edges { node { id name pattern confidence revoked } } }
        reports { edges { node { id name description published } } }
      }
    }
  }
}
"""

URL_QUERY = """
query($value: String!) {
  stixCyberObservables(filters: {
    mode: and,
    filters: [{key: "value", values: [$value]}],
    filterGroups: []
  }) {
    edges {
      node {
        id
        entity_type
        ... on Url { value }
        indicators { edges { node { id name pattern confidence revoked } } }
        reports { edges { node { id name description published } } }
      }
    }
  }
}
"""

DOMAIN_QUERY = """
query($value: String!) {
  stixCyberObservables(filters: {
    mode: and,
    filters: [{key: "value", values: [$value]}],
    filterGroups: []
  }) {
    edges {
      node {
        id
        entity_type
        ... on DomainName { value }
        indicators { edges { node { id name pattern confidence revoked } } }
        reports { edges { node { id name description published } } }
      }
    }
  }
}
"""

HASH_QUERY = """
query($value: String!) {
  stixCyberObservables(filters: {
    mode: and,
    filters: [{key: "hashes_value", values: [$value]}],
    filterGroups: []
  }) {
    edges {
      node {
        id
        entity_type
        ... on StixFile {
          name
          hashes { algorithm value }
        }
        indicators { edges { node { id name pattern confidence revoked } } }
        reports { edges { node { id name description published } } }
      }
    }
  }
}
"""


# ─── Client ───────────────────────────────────────────────────────────────────

class OpenCTIClient(BaseClient):
    """Client for OpenCTI GraphQL API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url.rstrip("/"), verify=verify, proxy=proxy)
        self._headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }

    def query(self, gql_query: str, variables: dict) -> dict:
        """Execute a GraphQL query against OpenCTI."""
        payload = {"query": gql_query, "variables": variables}
        return self._http_request(
            method="POST",
            url_suffix="/graphql",
            headers=self._headers,
            json_data=payload,
        )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def extract_observables(response: dict) -> list:
    """Pull observable nodes out of a GraphQL response."""
    try:
        edges = response["data"]["stixCyberObservables"]["edges"]
        return [edge["node"] for edge in edges]
    except (KeyError, TypeError):
        return []


def build_dbot_score(indicator: str, indicator_type, observables: list) -> Common.DBotScore:
    """Determine DBotScore based on indicator data from OpenCTI."""
    if not observables:
        score = Common.DBotScore.NONE
    else:
        # Check if any linked indicator is not revoked and has high confidence
        indicators = []
        for obs in observables:
            for edge in obs.get("indicators", {}).get("edges", []):
                indicators.append(edge["node"])

        malicious = any(
            not ind.get("revoked") and ind.get("confidence", 0) >= 75
            for ind in indicators
        )
        score = Common.DBotScore.BAD if malicious else Common.DBotScore.SUSPICIOUS if indicators else Common.DBotScore.GOOD

    return Common.DBotScore(
        indicator=indicator,
        indicator_type=indicator_type,
        integration_name="ThreatKiller",
        score=score,
    )


def format_observables(observables: list) -> list:
    """Flatten observable data for context output."""
    results = []
    for obs in observables:
        entry = {
            "ID": obs.get("id"),
            "EntityType": obs.get("entity_type"),
            "Value": obs.get("value") or obs.get("name"),
            "Indicators": [
                {
                    "ID": i["node"]["id"],
                    "Name": i["node"]["name"],
                    "Confidence": i["node"]["confidence"],
                    "Revoked": i["node"]["revoked"],
                }
                for i in obs.get("indicators", {}).get("edges", [])
            ],
            "Reports": [
                {
                    "ID": r["node"]["id"],
                    "Name": r["node"]["name"],
                    "Published": r["node"]["published"],
                }
                for r in obs.get("reports", {}).get("edges", [])
            ],
        }
        results.append(entry)
    return results


# ─── Command Functions ────────────────────────────────────────────────────────

def test_module(client: OpenCTIClient) -> str:
    """Test connectivity to OpenCTI."""
    test_query = """query { about { version } }"""
    try:
        result = client.query(test_query, {})
        if result.get("data"):
            return "ok"
        return f"Unexpected response: {result}"
    except Exception as e:
        return f"Connection failed: {e}"


def ip_command(client: OpenCTIClient, args: dict) -> list[CommandResults]:
    ips = argToList(args.get("ip"))
    results = []
    for ip in ips:
        response = client.query(IP_QUERY, {"value": ip})
        observables = extract_observables(response)
        formatted = format_observables(observables)
        dbot = build_dbot_score(ip, DBotScoreType.IP, observables)

        results.append(CommandResults(
            outputs_prefix="ThreatKiller.IP",
            outputs_key_field="Value",
            outputs=formatted if formatted else [{"Value": ip, "EntityType": "IPv4-Addr", "Indicators": [], "Reports": []}],
            readable_output=tableToMarkdown(
                f"OpenCTI IP Enrichment: {ip}",
                formatted or [{"Value": ip, "Result": "No data found in OpenCTI"}],
            ),
            indicator=Common.IP(
                ip=ip,
                dbot_score=dbot,
            ),
        ))
    return results


def url_command(client: OpenCTIClient, args: dict) -> list[CommandResults]:
    urls = argToList(args.get("url"))
    results = []
    for url in urls:
        response = client.query(URL_QUERY, {"value": url})
        observables = extract_observables(response)
        formatted = format_observables(observables)
        dbot = build_dbot_score(url, DBotScoreType.URL, observables)

        results.append(CommandResults(
            outputs_prefix="ThreatKiller.URL",
            outputs_key_field="Value",
            outputs=formatted if formatted else [{"Value": url, "EntityType": "URL", "Indicators": [], "Reports": []}],
            readable_output=tableToMarkdown(
                f"OpenCTI URL Enrichment: {url}",
                formatted or [{"Value": url, "Result": "No data found in OpenCTI"}],
            ),
            indicator=Common.URL(
                url=url,
                dbot_score=dbot,
            ),
        ))
    return results


def domain_command(client: OpenCTIClient, args: dict) -> list[CommandResults]:
    domains = argToList(args.get("domain"))
    results = []
    for domain in domains:
        response = client.query(DOMAIN_QUERY, {"value": domain})
        observables = extract_observables(response)
        formatted = format_observables(observables)
        dbot = build_dbot_score(domain, DBotScoreType.DOMAIN, observables)

        results.append(CommandResults(
            outputs_prefix="ThreatKiller.Domain",
            outputs_key_field="Value",
            outputs=formatted if formatted else [{"Value": domain, "EntityType": "Domain-Name", "Indicators": [], "Reports": []}],
            readable_output=tableToMarkdown(
                f"OpenCTI Domain Enrichment: {domain}",
                formatted or [{"Value": domain, "Result": "No data found in OpenCTI"}],
            ),
            indicator=Common.Domain(
                domain=domain,
                dbot_score=dbot,
            ),
        ))
    return results


def file_command(client: OpenCTIClient, args: dict) -> list[CommandResults]:
    hashes = argToList(args.get("file"))
    results = []
    for file_hash in hashes:
        response = client.query(HASH_QUERY, {"value": file_hash})
        observables = extract_observables(response)
        formatted = format_observables(observables)
        dbot = build_dbot_score(file_hash, DBotScoreType.FILE, observables)

        results.append(CommandResults(
            outputs_prefix="ThreatKiller.File",
            outputs_key_field="Value",
            outputs=formatted if formatted else [{"Value": file_hash, "EntityType": "StixFile", "Indicators": [], "Reports": []}],
            readable_output=tableToMarkdown(
                f"OpenCTI File Hash Enrichment: {file_hash}",
                formatted or [{"Value": file_hash, "Result": "No data found in OpenCTI"}],
            ),
            indicator=Common.File(
                dbot_score=dbot,
            ),
        ))
    return results


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("base_url", "").rstrip("/")
    api_token = params.get("credentials", {}).get("password") or params.get("api_token", "")
    verify_ssl = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    client = OpenCTIClient(
        base_url=base_url,
        api_token=api_token,
        verify=verify_ssl,
        proxy=proxy,
    )

    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "ip":
            return_results(ip_command(client, args))
        elif command == "url":
            return_results(url_command(client, args))
        elif command == "domain":
            return_results(domain_command(client, args))
        elif command == "file":
            return_results(file_command(client, args))
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command}. Error: {e}")


if __name__ == "__main__":
    main()