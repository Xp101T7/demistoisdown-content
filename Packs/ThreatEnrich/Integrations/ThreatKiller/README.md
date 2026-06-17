# ThreatKiller

## Overview
Generic threat intelligence feed integration that pulls indicators from a custom REST/JSON API using Bearer token authentication.

## Configuration

| Parameter | Description | Required |
|-----------|-------------|----------|
| API Base URL | Base URL of your threat intelligence API | True |
| Bearer Token | Bearer token for API authentication | True |
| Feed Endpoint | API endpoint to pull indicators from | True |
| Indicator Value Field | JSON field name containing the indicator value | True |
| Indicator Type Field | JSON field name containing the indicator type | False |
| Max Indicators Per Fetch | Maximum number of indicators per fetch | False |
| Fetch Indicators | Enable scheduled indicator fetching | False |
| Source Reliability | Reliability of the source | True |

## Commands

### threatkiller-get-indicators
Manually fetch and display indicators from the API.

**Arguments:**
| Argument | Description | Required |
|----------|-------------|----------|
| limit | Maximum number of indicators to return | False |

### ip
Enriches an IP address.

**Arguments:**
| Argument | Description | Required |
|----------|-------------|----------|
| ip | IP address to enrich | True |

### url
Enriches a URL.

**Arguments:**
| Argument | Description | Required |
|----------|-------------|----------|
| url | URL to enrich | True |

### domain
Enriches a domain.

**Arguments:**
| Argument | Description | Required |
|----------|-------------|----------|
| domain | Domain to enrich | True |

### file
Enriches a file hash.

**Arguments:**
| Argument | Description | Required |
|----------|-------------|----------|
| file | File hash (MD5, SHA1, SHA256) to enrich | True |

### cve
Enriches a CVE.

**Arguments:**
| Argument | Description | Required |
|----------|-------------|----------|
| cve | CVE ID to enrich e.g. CVE-2021-44228 | True |

### email
Enriches an email address.

**Arguments:**
| Argument | Description | Required |
|----------|-------------|----------|
| email | Email address to enrich | True |