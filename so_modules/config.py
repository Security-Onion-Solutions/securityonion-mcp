# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import os
import logging

# Configure logging
log = logging.getLogger(__name__)

# API Configuration
SO_CLIENT_ID = os.getenv("SO_CLIENT_ID")
SO_CLIENT_SECRET = os.getenv("SO_CLIENT_SECRET")
SO_API_ENDPOINT = os.getenv("SO_API_ENDPOINT")
SO_CA_CERT = os.getenv("SO_CA_CERT")

# SSL verification setting
raw_verify_ssl = os.getenv("SO_API_VERIFY_SSL")
if raw_verify_ssl is not None:
    if raw_verify_ssl.lower() in ('true', '1', 'yes'):
        SO_API_VERIFY_SSL = True
    elif raw_verify_ssl.lower() in ('false', '0', 'no'):
        SO_API_VERIFY_SSL = False
    else:
        SO_API_VERIFY_SSL = True
else:
    SO_API_VERIFY_SSL = True

# Default fields to include when filtering event payloads
DEFAULT_FIELDS = {
    "@timestamp", "client.name", "destination.ip", "destination.port", "dns.query.name",
    "event.category", "event.module", 
    "event.dataset", "event.severity", "event.severity_label", "file.mime_type", "file.name",
    "hash.md5", "hash.sha1", "host.mac", "http.method", "http.useragent",
    "http.virtual_host", "log.id.uid", "network.community_id", "network.protocol",
    "network.transport", "notice.message", "observer.name", "process.name", "process.executable", "rule.category", "rule.name",
    "rule.uuid", "software.name", "software.type", "software.version.unparsed",
    "source.ip", "source.port", "ssh.cypher_algorithm", "ssh.client",
    "ssh.server", "ssl.cipher", "ssl.server_name", "ssl.version", "user.name", "weird.name"
}
# --- Configuration Check ---

def check_config():
    """Checks if required configuration variables are set."""
    missing_vars = []
    if not SO_CLIENT_ID:
        missing_vars.append("SO_CLIENT_ID")
    if not SO_CLIENT_SECRET:
        missing_vars.append("SO_CLIENT_SECRET")
    if not SO_API_ENDPOINT:
        missing_vars.append("SO_API_ENDPOINT")

    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Callers can import and call check_config() if needed.