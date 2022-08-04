import os
import socket

# Host and AMS Net ID of the daemon:
LOG_DAEMON_HOST = os.environ.get("LOG_DAEMON_HOST", "172.21.32.90")
LOG_DAEMON_NET_ID = os.environ.get("LOG_DAEMON_NET_ID", f"{LOG_DAEMON_HOST}.1.1")

# The host name to report for daemon status messages:
LOG_DAEMON_HOST_NAME = os.environ.get("LOG_DAEMON_HOST_NAME", socket.gethostname())

# Route name to add to PLC:
LOG_DAEMON_ROUTE_NAME = os.environ.get("LOG_DAEMON_ROUTE_NAME", "ads-log-daemon")
# Encoding of messages from the PLC:
LOG_DAEMON_SOURCE_ENCODING = os.environ.get("LOG_DAEMON_SOURCE_ENCODING", "latin-1")

# Logstash target host and port:
LOG_DAEMON_TARGET_HOST = os.environ.get("LOG_DAEMON_TARGET_HOST", "ctl-logsrv01")
LOG_DAEMON_TARGET_PORT = int(os.environ.get("LOG_DAEMON_TARGET_PORT", 54321))
# Encoding for the generated logstash JSON messages:
LOG_DAEMON_ENCODING = os.environ.get("LOG_DAEMON_ENCODING", "utf-8")

# Reach out to a PLC by its service port at this rate:
LOG_DAEMON_INFO_PERIOD = int(os.environ.get("LOG_DAEMON_INFO_PERIOD", "60"))
# Search LDAP at this rate (every 15 mins) for new/removed hosts:
LOG_DAEMON_SEARCH_PERIOD = int(os.environ.get("LOG_DAEMON_SEARCH_PERIOD", "900"))

LOG_DAEMON_HOST_PREFIXES = os.environ.get(
    "LOG_DAEMON_HOST_PREFIXES", "plc-*,bhc-*"
).split(",")
LOG_DAEMON_LDAP_SERVER = os.environ.get(
    "LOG_DAEMON_LDAP_SERVER", "ldap://psldap1.pcdsn"
)
LOG_DAEMON_LDAP_SEARCH_BASE = os.environ.get(
    "LOG_DAEMON_LDAP_BASE", "ou=Subnets,dc=reg,o=slac"
)


# Are we within, e.g., a minute of what this machine's time shows?  Check for clock skew/
# missing NTP settings/etc
LOG_DAEMON_TIMESTAMP_THRESHOLD = int(
    os.environ.get("LOG_DAEMON_TIMESTAMP_THRESHOLD", 60)
)
# Query the PLC for project updates at this rate - this acts as a keepalive
# for the connection:
LOG_DAEMON_KEEPALIVE = int(os.environ.get("LOG_DAEMON_KEEPALIVE", 120))