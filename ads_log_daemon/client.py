from __future__ import annotations

import asyncio
import dataclasses
import datetime
import enum
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple, cast

import ads_async
from ads_async import constants, structs
from ads_async.asyncio.client import (
    AsyncioClientCircuit,
    AsyncioClientConnection,
    Client,
)
from ads_async.bin.info import get_plc_info as _get_plc_info
from ads_async.bin.route import add_route_to_plc
from ads_async.exceptions import RequestFailedError

from .config import (
    LOG_DAEMON_ENCODING,
    LOG_DAEMON_HOST,
    LOG_DAEMON_HOST_NAME,
    LOG_DAEMON_INFO_PERIOD,
    LOG_DAEMON_NET_ID,
    LOG_DAEMON_SOURCE_ENCODING,
    LOG_DAEMON_TARGET_HOST,
    LOG_DAEMON_TARGET_PORT,
    LOG_DAEMON_TIMESTAMP_THRESHOLD,
)

DESCRIPTION = __doc__

MSG_CLOCK_SETTINGS_BAD = (
    "{name} clock settings incorrect. Off by approximately {dt} seconds. "
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


class _UdpProtocol(asyncio.Protocol):
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


async def udp_transport_loop(queue: asyncio.Queue, host: str, port: int):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
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
    plc_identifier: PlcInformation,
    header: structs.AoEHeader,
    message: structs.AdsNotificationLogMessage,
    *,
    custom_message: Optional[str] = None,
    add_json: Optional[dict] = None,
    use_system_time: bool = False,
    severity: Optional[int] = None,
) -> Dict[str, Any]:
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
    custom_json.update(plc_identifier.asdict())
    msg = custom_message or message.message.decode(LOG_DAEMON_SOURCE_ENCODING).rstrip(
        "\x00"
    )
    subsystem = guess_subsystem(plc_identifier.host_name)
    if severity is None:
        severity = MessageType(int(message.unknown)).to_severity()

    return {
        "schema": "twincat-event-0",
        "ts": time.time() if use_system_time else message.timestamp.timestamp(),
        "severity": severity,
        "id": 0,  # hmm
        "event_class": "C0FFEEC0-FFEE-COFF-EECO-FFEEC0FFEEC0",
        "msg": msg,
        "plc": plc_identifier.name,
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


@dataclasses.dataclass
class PlcInformation:
    """
    PLC information container + helper.

    May be updated with either service port information via
    ``update_service_information`` or an ads-async asyncio TCP circuit
    as in ``update_device_info``.
    """

    #: The PLC Net ID
    net_id: str
    #: The PLC IP address (or hostname)
    address: str
    #: The PLC hostname
    host_name: str
    #: The name of the PLC according to TwinCAT
    name: Optional[str] = None
    #: The device version.
    version: Optional[str] = None
    #: The running project application name (TwinCAT_SystemInfoVarList._AppInfo.AppName)
    application_name: Optional[str] = None
    #: The PLC name according to device information (AdsDeviceInfoRequest)
    device_info_name: Optional[str] = None
    #: The loaded project name (TwinCAT_SystemInfoVarList._AppInfo.ProjectName)
    project_name: Optional[str] = None
    #: If the clock is set incorrectly (or significantly different) to
    #: ads-log-daemon.
    clock_incorrect: Optional[bool] = None
    #: The task names running on the PLC.
    task_names: List[str] = dataclasses.field(default_factory=list)
    #: Metadata from LDAP about the PLC host, if available.
    ldap_metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    #: Information retrieved from the UDP PLC service port.
    service_info: Dict[str, Any] = dataclasses.field(default_factory=dict)
    #: The service port indicated that its data came from here.
    service_ams_port: Optional[int] = None
    #: Number of attempts it took to get the PLC to respond to a service
    #: status query.
    service_query_fail_count: int = 0

    @property
    def tcp_address_tuple(self) -> Tuple[str, int]:
        return (self.address, constants.ADS_TCP_SERVER_PORT)

    def asdict(self) -> Dict[str, Any]:
        """
        PlcInformation items as a dictionary, excluding None values.

        Returns
        -------
        Dict[str, Any]
        """
        skip_keys = {
            "service_query_fail_count",
            "service_info",
            "ldap_metadata",
        }
        # Make ldap metadata keys top-level
        info = dict(self.ldap_metadata or {})
        info.update(dataclasses.asdict(self))
        return {
            key: value
            for key, value in info.items()
            if key not in skip_keys and value is not None
        }

    async def _get_plc_info_via_service_port_async(
        self,
        plc_hostname: str,
        timeout: float = 2.0,
    ):
        """
        async wrapper around the annoyingly synchronous UDP tools in ads-async.
        """

        def inner():
            try:
                return next(_get_plc_info(plc_hostname, timeout=timeout))
            except StopIteration:
                raise TimeoutError() from None

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, inner)

    async def update_service_information(
        self, retry_timeout: float = LOG_DAEMON_INFO_PERIOD
    ):
        """
        Update basic info that is available over the service port (UDP).

        This does not require an active circuit to run.
        """
        while True:
            try:
                service_info = await self._get_plc_info_via_service_port_async(
                    self.address
                )
            except TimeoutError:
                self.service_query_fail_count += 1
                if (self.service_query_fail_count % 60) == 0:
                    # First time and every hour, maybe.
                    logger.warning(
                        "%s (%s) may not be a PLC, or is not responding. "
                        "Waiting before retrying.",
                        self.host_name,
                        self.address,
                    )
                await asyncio.sleep(retry_timeout)
            else:
                break

        logger.debug("Host: %s Got PLC info: %s", self.address, service_info)
        source_net_id = service_info.get("source_net_id", None)
        if source_net_id and source_net_id != self.net_id:
            logger.warning(
                "%s PLC reports Net ID: %s Configured Net ID: %s; using PLC-reported Net ID.",
                self.host_name,
                source_net_id,
                self.net_id,
            )
            self.net_id = source_net_id

        plc_name = service_info.get("plc_name", None)
        if plc_name is not None:
            self.name = plc_name

        self.service_info = service_info
        return service_info

    async def update_device_info(self, circuit: AsyncioClientCircuit) -> Dict[str, Any]:
        """
        Update device information (project name, task names, etc.)

        Requires an active connection to the PLC via ads-async's
        AsyncioClientCircuit.
        """
        device_info = await circuit.get_device_information()
        project_name = await get_or_fallback(circuit.get_project_name(), "")
        app_name = await get_or_fallback(circuit.get_app_name(), "")
        task_names = await get_or_fallback(circuit.get_task_names(), [])

        logger.info(
            "Updating device information of %s: %s (version=%s name=%s)",
            self.host_name,
            self.service_info,
            device_info.version,
            device_info.name,
        )

        new_info = {
            "version": "{}.{}.{}".format(*device_info.version.as_tuple),
            "device_info_name": device_info.name,
            "project_name": project_name,
            "task_names": task_names,
            "application_name": app_name,
            # Can also get like `stLibVersion_Tc3_Module` or for LCLS general, etc.
        }
        changes = {
            attr: value
            for attr, value in new_info.items()
            if getattr(self, attr, None) != value
        }

        for attr, value in changes.items():
            old_value = getattr(self, attr)
            if old_value is not None:
                was_text = f" (was: {old_value})"
            else:
                was_text = ""
            logger.info(
                "%s information updated %s=%s%s",
                self.name,
                attr,
                value,
                was_text,
            )
            setattr(self, attr, value)

        return changes


class ClientLogger:
    """
    Per-PLC ads-async asyncio client-based logging.
    """

    handler: logging.Handler
    our_net_id: str
    add_log_filter: bool
    add_route: bool
    client: Optional[AsyncioClientConnection]
    circuit: Optional[AsyncioClientCircuit]
    plc: PlcInformation
    _log_task: Optional[asyncio.Task]
    running: bool

    def __init__(
        self,
        handler: logging.Handler,
        their_host: str,
        their_net_id: Optional[str] = None,
        our_net_id: Optional[str] = None,
        add_log_filter: bool = True,
        add_route: bool = True,
        ldap_metadata: Optional[dict] = None,
    ):
        self.handler = handler
        self.add_log_filter = add_log_filter
        self.add_route = add_route
        self.our_net_id = our_net_id or LOG_DAEMON_NET_ID
        self.client = None
        self.circuit = None
        self.udp_queue = None
        self.ldap_metadata = dict(ldap_metadata or {})
        self.running = False
        self.plc = PlcInformation(
            net_id=their_net_id or f"{their_host}.1.1",
            address=their_host,
            host_name=self.ldap_metadata.get("host_name", their_host),
            ldap_metadata=dict(ldap_metadata or {}),
        )
        self._log_task = None

    async def run(self):
        """Connect to the PLC via ads-async and run the logging loop."""
        self.running = True
        if self.add_log_filter:
            # Filter the circuit-level messages:
            self.handler.addFilter(
                ads_async.log.AddressFilter(self.our_net_id, self.plc.net_id)
            )

        plc_info = await self.plc.update_service_information()
        logger.debug("Host: %s Got PLC info: %s", self.plc.address, plc_info)

        if self.add_route:
            await self._add_route()

        async def start_logging():
            try:
                await self._log_loop()
            except asyncio.CancelledError:
                logger.warning(
                    "Log task canceled for %s (%s)", self.plc.name, self.plc.host_name
                )
            finally:
                logger.warning(
                    "Log task exiting for %s (%s)", self.plc.name, self.plc.host_name
                )

        async def keepalive():
            try:
                while self.running:
                    circuit = self.circuit
                    if circuit is None:
                        break
                    await asyncio.wait_for(
                        self.plc.update_device_info(circuit), timeout=30.0
                    )
                    await asyncio.sleep(30)
            except asyncio.CancelledError:
                logger.warning(
                    "Keepalive task canceled for %s (%s)",
                    self.plc.name,
                    self.plc.host_name,
                )
            finally:
                logger.warning(
                    "Keepalive task exiting for %s (%s)",
                    self.plc.name,
                    self.plc.host_name,
                )

        try:
            async with Client(
                self.plc.tcp_address_tuple, our_net_id=self.our_net_id
            ) as self.client:
                async with self.client.get_circuit(self.plc.net_id) as self.circuit:
                    log_task = asyncio.create_task(start_logging())
                    self._log_task = log_task
                    try:
                        await keepalive()
                    except asyncio.CancelledError:
                        logger.debug("%s task cancelled", self.plc.address)
                    log_task.cancel()
        finally:
            self.running = False

    async def log(self, message: Dict[str, Any]):
        """Ship a message to logstash via the UDP queue."""
        if self.udp_queue is None:
            self.udp_queue = asyncio.Queue()
            asyncio.create_task(
                udp_transport_loop(
                    self.udp_queue, LOG_DAEMON_TARGET_HOST, LOG_DAEMON_TARGET_PORT
                )
            )

        await self.udp_queue.put(message)

    async def _add_route(self):
        """Add a route for the log daemon to the PLC."""

        def inner() -> Dict[str, Any]:
            result = add_route_to_plc(
                self.plc.address,
                source_net_id=self.our_net_id,
                source_name=LOG_DAEMON_HOST,
                route_name=LOG_DAEMON_HOST,  # LOG_DAEMON_ROUTE_NAME
            )
            logger.info("Added route to PLC %s", self.plc.host_name)
            return result

        logger.info("Adding route to PLC %s in background...", self.plc.address)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, inner)

    async def _check_for_clock_skew(
        self,
        header: structs.AoEHeader,
        message: structs.AdsNotificationLogMessage,
    ):
        """Check the log message for clock skew / bad time zone / ntp settings."""
        if self.plc.clock_incorrect is not None:
            # Only check once
            return

        dt = timestamp_delta_seconds(message.timestamp)
        self.plc.clock_incorrect = abs(dt) > LOG_DAEMON_TIMESTAMP_THRESHOLD
        if not self.plc.clock_incorrect:
            return

        clock_settings_wrong_message = MSG_CLOCK_SETTINGS_BAD.format(
            header=header, message=message, dt=int(dt), **self.plc.asdict()
        )
        await self.log(
            to_logstash(
                self.plc,
                header,
                message,
                use_system_time=True,
                custom_message=clock_settings_wrong_message,
                severity=3,
            )
        )

    async def handle_message(
        self,
        header: structs.AoEHeader,
        message: structs.AdsNotificationLogMessage,
    ):
        """
        Handle a log message coming in from the PLC.

        Parameters
        ----------
        header : structs.AoEHeader
            The AoE header associated with the message.
        message : structs.AdsNotificationLogMessage
            The log message itself.
        """
        logger.info(
            "%s Log message %s ==> %s",
            self.plc.host_name,
            message,
            to_logstash(self.plc, header, message),
        )

        await self._check_for_clock_skew(header, message)
        await self.log(
            to_logstash(
                self.plc,
                header,
                message,
                use_system_time=bool(self.plc.clock_incorrect),
            )
        )

    async def _log_loop(
        self,
    ):
        circuit = self.circuit
        if circuit is None:
            return

        await self.plc.update_service_information()
        await self.log(
            create_status_message(
                message=f"Logging daemon connected to and monitoring {self.plc.name!r}",
                custom_json=self.plc.asdict(),
            )
        )

        # Give some time for initial notifications, and prune any stale
        # ones from previous sessions:
        await asyncio.sleep(1.0)
        await circuit.prune_unknown_notifications()
        logger.info(
            "%s: Enabling the log system and waiting for messages...",
            self.plc.host_name,
        )

        notification = circuit.enable_log_system()
        async for header, _, sample in notification:
            try:
                header = cast(structs.AoEHeader, header)
                sample = cast(structs.AdsNotificationSample, sample)
                message = sample.as_log_message()
                await self.handle_message(header, message)
            except Exception:
                logger.exception(
                    "%s Bad log message sample or failed to send: %s",
                    self.plc.host_name,
                    sample,
                )

    async def stop(self):
        """Stop the logging mechanism."""
        if not self.running:
            return

        self.running = False
        self.client = None
        self.circuit = None

        log_task = self._log_task
        if log_task is not None:
            log_task.cancel()
            self._log_task = None
