# Onion Query Language (OQL) - Condensed Reference

## Core Concepts
OQL starts with standard Lucene query syntax and adds optional segments that control what Dashboards does with the query results.

## Basic Syntax
```
<lucene_query> [| <segment> [| <segment> ...]]
```

## Lucene Query Syntax (Left of pipe |)
- Field searches: `field:value` (e.g., `destination.ip:10.0.0.1`)
- Boolean operators: AND, OR, NOT (e.g., `source.ip:192.168.1.1 AND destination.port:80`)
- Wildcards: ? (single character), * (multiple characters)
- Phrase searches: Use quotes (e.g., `message:"login failed"`)
- Range searches: `field:[lower TO upper]` (e.g., `status:[400 TO 499]`)
- Grouping: Use parentheses (e.g., `(source.ip:10.0.0.1 OR source.ip:10.0.0.2) AND destination.port:80`)

## Common Tags
Security Onion uses tags to categorize data by type. Using tags in queries is often more efficient than using event.dataset fields. Common tags include:

### Protocol Tags
| Tag | Description | Instead of |
|-----|-------------|------------|
| `conn` | Connection metadata | `event.dataset:conn` |
| `dns` | DNS protocol data | `event.dataset:dns` |
| `http` | HTTP protocol data | `event.dataset:http` |
| `http2` | HTTP/2 protocol data | `event.dataset:http2` |
| `ssl` | SSL/TLS protocol data | `event.dataset:ssl` |
| `ssh` | SSH protocol data | `event.dataset:ssh` |
| `file` | File transfer data | `event.dataset:files` |
| `smb_files` | SMB file operations | `event.dataset:smb_files` |
| `smb_mapping` | SMB mapping data | `event.dataset:smb_mapping` |
| `stun` | STUN protocol data | `event.dataset:stun` |
| `dhcp` | DHCP protocol data | `event.dataset:dhcp` |
| `quic` | QUIC protocol data | `event.dataset:quic` |
| `tunnel` | Tunneled connections | `event.dataset:tunnel` |
| `x509` | Certificate data | `event.dataset:x509` |

### Alert & Security Tags
| Tag | Description | Instead of |
|-----|-------------|------------|
| `alert` | All alerts (Suricata, etc.) | `event.dataset:suricata.alert` |
| `notice` | Zeek notices | `event.dataset:notice` |
| `weird` | Unusual activity detected | `event.dataset:weird` |
| `dpd` | Dynamic protocol detection | `event.dataset:dpd` |
| `auth` | Authentication events | `event.dataset:auth` |

### System & Infrastructure Tags
| Tag | Description | Instead of |
|-----|-------------|------------|
| `elastic-agent` | Elastic Agent logs | `event.module:elastic_agent` |
| `kafka` | Kafka message broker logs | Kafka-related event.dataset fields |
| `syslog` | System logs | Various syslog event.dataset fields |
| `access` | Access logs | `event.dataset:access` |
| `fleet_server` | Elastic Fleet server logs | `event.module:fleet_server` |
| `audit` | Audit logs | `event.dataset:audit` |
| `application` | Application logs | `event.dataset:application` |

### Special Purpose Tags
| Tag | Description | Instead of |
|-----|-------------|------------|
| `strelka` | File analysis results | `event.module:strelka` |
| `zeek` | All Zeek-generated data | Various Zeek-related event.dataset values |
| `suricata` | All Suricata-generated data | Various Suricata-related event.dataset values |
| `so-kratos` | Kratos authentication service | Kratos-related event.dataset fields |
| `so-hydra` | Hydra service logs | Hydra-related event.dataset fields |
| `software` | Software identification | `event.dataset:software` |

### Industrial Control System (ICS) Tags
| Tag | Description | Instead of |
|-----|-------------|------------|
| `ics` | Industrial Control Systems data | Various ICS event.dataset fields |
| `bsap_ip_header` | BSAP/IP protocol header data | `event.dataset:bsap_ip_header` |

## Time Format Requirements for query_events

**IMPORTANT**: The `query_events` tool requires specific time formats:
- **Relative times**: `-6h`, `-5m`, `-7d`, `-30d` (negative values for past times)
- **Keywords**: `now`, `today`
- **Absolute format**: `YYYY/MM/DD HH:MM:SS AM/PM` (e.g., `2025/06/09 08:00:00 AM`)

**DO NOT use ISO 8601 format** (e.g., `2025-06-09T08:00:00`) - this will cause an error!

### Examples:
```python
# CORRECT time formats:
query_events(oql_query="tags:alert", start_time="-24h", end_time="now")
query_events(oql_query="tags:conn", start_time="-7d", end_time="-1d")
query_events(oql_query="source.ip:10.0.0.1", start_time="2025/06/09 08:00:00 AM", end_time="2025/06/09 10:00:00 AM")

# INCORRECT - DO NOT USE:
query_events(oql_query="tags:alert", start_time="2025-06-09T08:00:00", end_time="2025-06-09T10:00:00")
```

## OQL Segments (Right of pipe |)

### sortby
Sorts results by specified field(s). Default order is descending. Use ^ for ascending.
```
| sortby field1 field2^
```

### groupby
Groups (aggregates) results by specified field(s).
```
| groupby field1 field2
```

Multiple groupby segments create independent data tables:
```
| groupby field1 | groupby field2
```
## Example Queries
```
destination.port:80 AND event.dataset:conn | groupby network.protocol
destination.port:80 AND tags:conn | groupby network.protocol destination.port
tags:alert | groupby event.module
tags:conn | groupby source.ip destination.ip
```

## Playbook Feature

Security Onion MCP includes a playbook feature for guided investigation of alerts. When you have an alert ID:

### Using get_playbook_questions Tool
```
# Get investigation questions for an alert. The alert id would be the rule.uuid from the actual alert.
get_playbook_questions(alert_id="6F64990A-ACDA-40B6-AB71-134C073013B5")

# Get questions from only a specific playbook (0-based index)
get_playbook_questions(alert_id="alert-123", playbook_index=0)
```

### What the Tool Returns
The tool returns investigation questions from playbooks associated with the alert:
- **question**: The investigation question to answer
- **context**: Why this question is important for the investigation
- **answer_sources**: Where to find relevant data (e.g., network logs, firewall logs)
- **suggested_query**: A template query that may contain variables
- **time_range**: Suggested time range for the investigation (e.g., "+/-1h")

### Using Playbook Questions
After retrieving the questions:
1. Review the questions and their context
2. Build appropriate OQL queries based on the specific alert data
3. Consider the suggested time ranges and data sources
4. Execute queries using `query_events` to answer the investigation questions
