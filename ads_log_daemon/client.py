import asyncio
import datetime
import enum
import json
import logging
import os
import socket
import sys
import time
from typing import Optional

import ads_async
import ldap
from ads_async import constants, structs
from ads_async.asyncio.client import Client
from ads_async.bin.info import get_plc_info as _get_plc_info
from ads_async.bin.route import add_route_to_plc
from ads_async.exceptions import RequestFailedError

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


MSG_CLOCK_SETTINGS_BAD = (
    "{plc_name} clock settings incorrect. Off by approximately {dt} seconds. "
    "Log daemon will use its system timestamp."
)

logger = logging.getLogger(__name__)


class MessageType(enum.IntFlag):
    """This may be related to the identifier - not sure yet."""

    hint = 0x01
    warn = 0x02
    error = 0x04
    log = 0x10
    msgbox = 0x20
    resource = 0x40
    string = 0x80

    def to_severity(self) -> int:
        """Guess at target severity."""
        # Critical is 4...
        if MessageType.error in self:
            return 3
        if MessageType.warn in self:
            return 2
        if MessageType.hint in self:
            return 1
        return 0


def guess_subsystem(host: str) -> str:
    """Guess the subsystem based on the host name."""
    host = host.replace("_", "-").lower()
    if "-vac" in host:
        return "Vacuum"
    if "-optics" in host:
        return "Optics"
    if "-motion" in host:
        return "Motion"
    if "-vonhamos" in host:
        return "Motion"
    if "-sds" in host:
        return "SDS"
    try:
        return host.split("-")[1].upper()
    except Exception:
        return "PythonLogDaemon"


class LDAPHelper:
    """
    LDAP helper class to find PLCs.

    Parameters
    ----------
    server : str, optional
        LDAP server, defaults to LOG_DAEMON_LDAP_SERVER.

    base : str, optional
        LDAP base to search, defaults to LOG_DAEMON_LDAP_SEARCH_BASE.

    host_prefixes : list, optional
        List of host prefixes, including glob syntax.
        Defaults to comma-delimited LOG_DAEMON_HOST_PREFIXES.

    Attributes
    ----------
    hosts : dict
        Common host name to dictionary of information, with keys
        ``{"location", "desc", "mac", "host_name", "ip_address"}``
    """

    def __init__(
        self,
        server=LOG_DAEMON_LDAP_SERVER,
        base=LOG_DAEMON_LDAP_SEARCH_BASE,
        host_prefixes=LOG_DAEMON_HOST_PREFIXES,
    ):
        self.client = ldap.initialize(server)
        self.hosts = {}
        self.base = base
        self.host_prefixes = host_prefixes
        self._last_hosts = set()

    def update_hosts(self):
        """
        Update hosts dictionary with the LDAP client.

        After an update, refer to the ``.hosts`` dictionary.

        Returns
        -------
        removed : set
            Removed host names.

        added : set
            Added host names.
        """
        host_filter = "".join(
            f"(cn={host_prefix})" for host_prefix in self.host_prefixes
        )
        search_filter = f"(|{host_filter})"

        def get_value(entry, key):
            value, *_ = entry.get(key, [b""])
            if isinstance(value, bytes):
                return value.decode("ascii")
            return value

        found_hosts = set()
        added_hosts = set()
        for dn, entry in self.client.search_s(
            self.base, ldap.SCOPE_SUBTREE, search_filter
        ):
            ip_address = get_value(entry, "ipHostNumber")
            common_name = get_value(entry, "cn")

            is_new = (
                common_name not in self.hosts
                or ip_address != self.hosts[common_name]["ip_address"]
            )
            if is_new:
                added_hosts.add(common_name)
            self.hosts[common_name] = dict(
                location=get_value(entry, "location"),
                desc=get_value(entry, "description"),
                mac=get_value(entry, "macAddress"),
                host_name=common_name,
                ip_address=ip_address,
            )
            found_hosts.add(common_name)

        removed_hosts = self._last_hosts - found_hosts
        for host in removed_hosts:
            self.hosts.pop(host, None)

        self._last_hosts = added_hosts
        return removed_hosts, added_hosts


class _UdpProtocol:
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        ...

    def error_received(self, ex):
        logger.error("UDP error %s", ex)

    def connection_lost(self, ex):
        logger.error("UDP error / closed? %s", ex)


async def udp_transport_loop(queue, host, port):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        _UdpProtocol,
        remote_addr=(host, port),
    )
    while True:
        try:
            item = await queue.get()
            json_item = json.dumps(item).encode(LOG_DAEMON_ENCODING)
            transport.sendto(json_item)
        except Exception as ex:
            logger.error("Failed to send message: %s", ex)
            logger.debug("Failed to send message: %s", ex, exc_info=True)
            await asyncio.sleep(0.01)


def to_custom_json(
    header: structs.AoEHeader, message: structs.AdsNotificationLogMessage
) -> dict:
    return {
        "port_name": message.sender_name.decode(LOG_DAEMON_SOURCE_ENCODING),
        "ams_port": message.ams_port,
        "source": repr(header.source),
        "identifier": message.unknown,
    }


def to_logstash(
    plc_identifier: dict,
    header: structs.AoEHeader,
    message: structs.AdsNotificationLogMessage,
    *,
    custom_message: Optional[str] = None,
    add_json: Optional[dict] = None,
    use_system_time: bool = False,
    severity: Optional[int] = None,
) -> dict:
    # From:
    # AdsNotificationLogMessage(
    #   timestamp=datetime.datetime,
    #   unknown=84, ams_port=500,
    #   sender_name=b'TCNC',
    #   message_length=114, message=b'\'Axis 1\' (Axis-ID: 1): The axis needs the
    #   "Feed Forward Permission" for forward positioning (error-code: 0x4358) !'
    #  )
    # To:
    # (f'{"schema":"twincat-event-0","ts":{twincat_now},"plc":"LogTest",'
    #   '"severity":4,"id":0,'
    #   '"event_class":"C0FFEEC0-FFEE-COFF-EECO-FFEEC0FFEEC0",'
    #   '"msg":"Critical (Log system test.)",'
    #   '"source":"pcds_logstash.testing.fbLogger/Debug",'
    #   '"event_type":3,"json":"{}"}'
    #   ),
    custom_json = to_custom_json(header, message)
    custom_json.update(add_json or {})
    msg = custom_message or message.message.decode(LOG_DAEMON_SOURCE_ENCODING).rstrip(
        "\x00"
    )
    subsystem = guess_subsystem(plc_identifier["host_name"])
    if severity is None:
        severity = MessageType(int(message.unknown)).to_severity()

    return {
        "schema": "twincat-event-0",
        "ts": time.time() if use_system_time else message.timestamp.timestamp(),
        "severity": severity,
        "id": 0,  # hmm
        "event_class": "C0FFEEC0-FFEE-COFF-EECO-FFEEC0FFEEC0",
        "msg": msg,
        "plc": plc_identifier["plc_name"],
        "source": f"logging.aggregator/{subsystem}",
        "event_type": 3,  # 3=message_sent
        "json": json.dumps(custom_json),
    }


def create_status_message(
    message: str,
    *,
    custom_json: Optional[dict] = None,
    severity: Optional[int] = None,
) -> dict:
    return {
        "schema": "twincat-event-0",
        "ts": time.time(),
        "severity": severity if severity is not None else 0,
        "id": 0,  # hmm
        "event_class": "C0FFEEC0-FFEE-COFF-EECO-FFEEC0FFEEC1",
        "msg": message,
        "plc": LOG_DAEMON_HOST_NAME,
        "source": "logging.aggregator/LogDaemon",
        "event_type": 3,  # 3=message_sent
        "json": json.dumps(custom_json or {}),
    }


def timestamp_delta_seconds(timestamp: datetime.datetime) -> float:
    """What's the time difference, in seconds, of our clock vs the timestamp in the message?"""
    return (datetime.datetime.now() - timestamp).total_seconds()


async def get_or_fallback(coro, fallback, log: bool = False):
    """Get the result of the coroutine or fall back to `fallback`."""
    try:
        return await coro
    except RequestFailedError as ex:
        logger.debug("Failed to get %s (%s)", coro, ex)
        if log:
            logger.warning("Failed to get %s (%s)", coro, ex)
        return fallback


async def get_plc_info(*args, **kwargs):
    def inner():
        try:
            return next(_get_plc_info(*args, **kwargs))
        except StopIteration:
            raise TimeoutError() from None

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, inner)


async def client_loop(
    their_host: str,
    their_net_id: Optional[str] = None,
    our_net_id: Optional[str] = None,
    add_log_filter: bool = True,
    add_route: bool = True,
    metadata: Optional[dict] = None,
):
    our_net_id = our_net_id or LOG_DAEMON_NET_ID
    their_net_id = their_net_id or f"{their_host}.1.1"
    metadata = dict(metadata or {})

    if add_log_filter:
        # Filter the circuit-level messages:
        handler.addFilter(ads_async.log.AddressFilter(our_net_id, their_net_id))
    plc_host_name = metadata.get("host_name", None)

    warn_count = 0
    while True:
        try:
            plc_info = await get_plc_info(their_host)
        except TimeoutError:
            if (warn_count % 60) == 0:
                # First time and every hour, maybe.
                logger.warning(
                    "%s (%s) may not be a PLC, or is not responding. "
                    "Waiting before retrying.",
                    plc_host_name,
                    their_host,
                )
            warn_count += 1
            await asyncio.sleep(LOG_DAEMON_INFO_PERIOD)
        else:
            break

    logger.debug("Host: %s Got PLC info: %s", their_host, plc_info)
    if plc_info["source_net_id"] != their_net_id:
        logger.warning(
            "%s PLC reports Net ID: %s Configured Net ID: %s; using PLC-reported Net ID.",
            plc_host_name,
            plc_info["source_net_id"],
            their_net_id,
        )
        their_net_id = plc_info["source_net_id"]

    if add_route:
        logger.info("Adding route to PLC %s", their_host)
        add_route_to_plc(
            their_host,
            source_net_id=our_net_id,
            source_name=LOG_DAEMON_HOST,
            route_name=LOG_DAEMON_HOST,  # LOG_DAEMON_ROUTE_NAME
        )
        logger.info("Added route to PLC %s", plc_host_name)

    udp_queue = asyncio.Queue()
    asyncio.create_task(
        udp_transport_loop(udp_queue, LOG_DAEMON_TARGET_HOST, LOG_DAEMON_TARGET_PORT)
    )

    plc_identifier = {
        "net_id": plc_info["source_net_id"],
        "address": their_host,
        "host_name": plc_host_name,
    }
    clock_incorrect = None
    # This should all probably be moved out into a class or refactored, yuck

    async def handle_message(header, message):
        nonlocal clock_incorrect
        logger.info(
            "%s Log message %s ==> %s",
            plc_host_name,
            message,
            to_logstash(plc_identifier, header, message, add_json=metadata),
        )

        if clock_incorrect is None:
            dt = timestamp_delta_seconds(message.timestamp)
            clock_incorrect = abs(dt) > LOG_DAEMON_TIMESTAMP_THRESHOLD
            if clock_incorrect:
                custom_msg = MSG_CLOCK_SETTINGS_BAD.format(
                    header=header, message=message, dt=int(dt), **plc_identifier
                )
                await udp_queue.put(
                    to_logstash(
                        plc_identifier,
                        header,
                        message,
                        use_system_time=True,
                        custom_message=custom_msg,
                        add_json=metadata,
                        severity=3,
                    )
                )

        await udp_queue.put(
            to_logstash(
                plc_identifier,
                header,
                message,
                use_system_time=clock_incorrect,
                add_json=metadata,
            )
        )

    async def circuit_main(circuit):
        device_info = await circuit.get_device_information()
        project_name = await get_or_fallback(circuit.get_project_name(), "")
        app_name = await get_or_fallback(circuit.get_app_name(), "")
        task_names = await get_or_fallback(circuit.get_task_names(), [])

        logger.info("%s Service PLC info: %s", plc_host_name, plc_info)
        logger.info(
            "%s PLC Device info: %s (%s)",
            plc_host_name,
            device_info.version,
            device_info.name,
        )
        # Project name such as "Project1"
        logger.info("%s Project name: %r", plc_host_name, project_name)
        # Application name such as "Port_851"
        logger.info("%s Application name: %r", plc_host_name, app_name)
        # Task names such as ["MAIN_PlcTask", ...]
        logger.info("%s Task names: %s", plc_host_name, task_names)

        plc_identifier.update(
            {
                "plc_name": plc_info["plc_name"],
                "version": "{}.{}.{}".format(*device_info.version.as_tuple),
                "device_info_name": device_info.name,
                "project_name": project_name,
                "task_names": task_names,
                # Can also get like `stLibVersion_Tc3_Module` or for LCLS general, etc.
            }
        )
        logger.info("PLC identifier: %s", plc_identifier)

        await udp_queue.put(
            create_status_message(
                message=f'Logging daemon connected to and monitoring {plc_info["plc_name"]!r}',
                custom_json=plc_identifier,
            )
        )

        # Give some time for initial notifications, and prune any stale
        # ones from previous sessions:
        await asyncio.sleep(1.0)
        await circuit.prune_unknown_notifications()
        logger.info(
            "%s: Enabling the log system and waiting for messages...", plc_host_name
        )

        async for header, _, sample in circuit.enable_log_system():
            try:
                message = sample.as_log_message()
                await handle_message(header, message)
            except Exception:
                logger.exception(
                    "%s Bad log message sample or failed to send: %s",
                    plc_host_name,
                    sample,
                )

    async with Client(
        (their_host, constants.ADS_TCP_SERVER_PORT), our_net_id=our_net_id
    ) as client:
        async with client.get_circuit(their_net_id) as circuit:
            try:
                await circuit_main(circuit)
            except asyncio.CancelledError:
                logger.debug("%s task cancelled", their_host)


async def main_manual(client_addresses):
    """Run the daemon with manually-specified list of client addresses."""
    if len(client_addresses) == 0:
        logger.error("No client addresses given; exiting")
        return
    if client_addresses[0].startswith("-"):
        logger.error("I need to add argparser")
        return

    tasks = [asyncio.create_task(client_loop(addr)) for addr in client_addresses]
    await asyncio.gather(*tasks)


async def main_ldap():
    """Run the daemon using the configured LDAP settings to search for PLCs."""
    ld = LDAPHelper()
    tasks = {}

    def describe_host(host):
        try:
            info = ld.hosts[host]
        except KeyError:
            return host

        return (
            "host={host_name} ({ip_address}/{mac}) {desc!r} @ {location!r}"
            "".format(**info)
        )

    def prune_tasks():
        for host, task in list(tasks.items()):
            if task.done():
                logger.info("Removing dead task for %s", describe_host(host))
                tasks.pop(host)

    while True:
        logger.info("Looking for new hosts with LDAP...")
        removed_hosts, added_hosts = ld.update_hosts()
        for host in removed_hosts:
            task = tasks.pop(host, None)
            if task is not None:
                tasks.cancel()

        await asyncio.sleep(1.0)
        missing_tasks = set(ld.hosts) - set(tasks)
        for host in missing_tasks:
            info = ld.hosts[host]
            logger.info("New host: %s", describe_host(host))
            coro = client_loop(info["ip_address"], metadata=info)
            tasks[host] = asyncio.create_task(coro, name=f"log_{host}")

        try:
            for coro in asyncio.as_completed(
                set(tasks.values()), timeout=LOG_DAEMON_SEARCH_PERIOD
            ):
                try:
                    await coro
                except asyncio.TimeoutError:
                    raise
                except Exception:
                    prune_tasks()
        except asyncio.TimeoutError:
            ...

        prune_tasks()
        await asyncio.sleep(1.0)


if __name__ == "__main__":
    logging.basicConfig(format=ads_async.log.PLAIN_LOG_FORMAT, level="INFO")
    handler = ads_async.log.configure(level="INFO")
    logging.getLogger("ads_async.bin.utils").setLevel(logging.WARNING)
    # TODO argparse
    if "--ldap" in sys.argv:
        value = asyncio.run(main_ldap(), debug=True)
    else:
        value = asyncio.run(main_manual(sys.argv[1:]), debug=True)
