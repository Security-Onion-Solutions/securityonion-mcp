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

### Alert Severity
There 4 severities under event.severity_label:
- low
- medium
- high
- critical

## Alert Triage
Use get_playbook_questions and answer them when doing detailed analysis of a single alert.

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

## Alert Acknowledgment Feature

Security Onion MCP includes an alert acknowledgment tool for managing alert status. This tool allows you to mark alerts as acknowledged (reviewed) or unacknowledged.

### Using acknowledge_alerts Tool

The `acknowledge_alerts` tool helps manage alert visibility on Security Onion Alert screens. Acknowledged alerts won't appear on users' Alert screens after refresh.

### Tool Parameters
- **acknowledge** (bool): True to acknowledge, False to unacknowledge alerts
- **search_filter** (str): OQL query to find matching alerts
- **event_filter** (dict): Additional field:value pairs for filtering
- **date_range** (str): Date range in format "YYYY/MM/DD HH:MM:SS AM/PM - YYYY/MM/DD HH:MM:SS AM/PM"
- **date_range_format** (str): Format of date range (default: "2006/01/02 3:04:05 PM")
- **timezone** (str): Timezone for date range (default: "America/New_York")
- **escalate** (bool): Filter by escalation status

### Common Use Cases

#### Acknowledge a specific alert by log.id.uid
```python
# Most direct method - use event_filter with the alert's unique ID
acknowledge_alerts(
    acknowledge=True,
    search_filter="tags:alert",
    event_filter={"log.id.uid": "593101912711664"}
)
```

#### Acknowledge all unacknowledged alerts from a specific rule
```python
acknowledge_alerts(
    acknowledge=True,
    search_filter="tags:alert AND NOT event.acknowledged:true AND rule.uuid:bf86ef21-41e6-417b-9a05-b9ea6bf28a38"
)
```

#### Acknowledge alerts with specific criteria
```python
acknowledge_alerts(
    acknowledge=True,
    search_filter="tags:alert AND NOT event.acknowledged:true",
    event_filter={"rule.name": "Security Onion - SOC Login Failure", "event.module": "sigma"}
)
```

#### Acknowledge alerts with special characters in rule names
```python
# For rule names with asterisks (*) or other special characters
# Use event_filter instead of including in search_filter
acknowledge_alerts(
    acknowledge=True,
    search_filter="tags:alert AND NOT event.acknowledged:true",
    event_filter={"rule.name": "GPL ICMP PING *NIX"}
)

# Note: Special characters like *, ?, [, ], and others can cause issues
# when used directly in search_filter. Always use event_filter for exact matches.
```

#### Bulk acknowledge false positives
```python
acknowledge_alerts(
    acknowledge=True,
    search_filter="tags:alert AND source.ip:10.0.0.100 AND destination.port:445",
    date_range="2024/12/03 00:00:00 AM - 2024/12/03 11:59:59 PM"
)
```

#### Unacknowledge previously reviewed alerts for re-investigation
```python
acknowledge_alerts(
    acknowledge=False,
    search_filter="tags:alert AND event.acknowledged:true AND rule.name:\"Suspicious Process Creation\"",
    date_range="2024/12/01 00:00:00 AM - 2024/12/04 11:59:59 PM"
)
```

### Return Values
The tool returns a dictionary containing:
- **updated**: Number of alerts successfully updated
- **failed**: Number of alerts that failed to update
- **errors**: List of any errors encountered
- **completeTime**: When the operation completed
- **elapsedMs**: Duration of the operation in milliseconds

### Best Practices
1. Always include `tags:alert` in your search_filter to ensure you're only targeting alerts
2. Use `NOT event.acknowledged:true` to find unacknowledged alerts
3. Test your search_filter with `query_events` first to verify it matches the intended alerts
4. Consider using date ranges to limit the scope when dealing with large alert volumes
5. Check the return values to ensure all intended alerts were updated successfully

### Troubleshooting Alert Acknowledgment

#### Common Issues and Solutions

1. **"Invalid input parameters" error**
   - Ensure you're using the `event_filter` parameter for specific field matches
   - Use `search_filter="tags:alert"` as the base query
   - Example: To ack by log.id.uid, use `event_filter={"log.id.uid": "YOUR_ID"}`

2. **403 Forbidden error**
   - Check API credentials have proper permissions for alert acknowledgment
   - Verify the SO_CLIENT_ID and SO_CLIENT_SECRET are correctly configured

3. **No alerts updated (updatedCount: 0)**
   - Verify the alert hasn't already been acknowledged
   - Check that your search criteria match existing alerts
   - Use `query_events` to test your search criteria first

4. **Finding the right identifier**
   - Use `log.id.uid` for Suricata/Zeek alerts (found in alert details)
   - Use `rule.uuid` to acknowledge all alerts from a specific rule
   - Combine multiple criteria in `event_filter` for precise targeting

5. **Handling special characters in field values**
   - Rule names with special characters (*, ?, [, ], etc.) should use `event_filter`
   - Avoid putting values with wildcards directly in `search_filter`
   - Example: For "GPL ICMP PING *NIX", use `event_filter={"rule.name": "GPL ICMP PING *NIX"}`
   - This prevents the asterisk from being interpreted as a wildcard
