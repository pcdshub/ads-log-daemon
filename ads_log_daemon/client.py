from __future__ import annotations

import asyncio
import dataclasses
import datetime
import enum
import json
import logging
import time
from typing import Any, Dict, Optional, Tuple, cast

import ads_async
from ads_async import constants, structs
from ads_async.asyncio.client import (
    AsyncioClientCircuit,
    AsyncioClientConnection,
    Client,
)
from ads_async.bin.info import get_plc_info as _get_plc_info
from ads_async.bin.route import add_route_to_plc
from ads_async.exceptions import DisconnectedError, RequestFailedError

from .config import (
    LOG_DAEMON_HOST,
    LOG_DAEMON_HOST_NAME,
    LOG_DAEMON_INFO_PERIOD,
    LOG_DAEMON_KEEPALIVE,
    LOG_DAEMON_NET_ID,
    LOG_DAEMON_SOURCE_ENCODING,
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

    # TODO: always using system time for now
    # timestamp = time.time() if use_system_time else message.timestamp.timestamp()
    timestamp = time.time()

    return {
        "schema": "twincat-event-0",
        "ts": timestamp,
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
    source_detail: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a logging.aggregator status message for logstash.

    Parameters
    ----------
    message : str
        The message to send to logstash.
    custom_json : dict, optional
        Custom JSON to serialize and send to logstash.
    severity : int, optional
        Severity level for the message.
    source_detail : str, optional
        Details about the source of the message.
        Formatted as: ``logging.aggregator/LogDaemon.{source_detail}``.

    Returns
    -------
    loggable_obj : dict
        Serializable dictionary that conforms to the TwinCAT event schema.
    """
    if source_detail is None:
        source_suffix = ""
    else:
        source_suffix = f".{source_detail}"

    return {
        "schema": "twincat-event-0",
        "ts": time.time(),
        "severity": severity if severity is not None else 0,
        "id": 0,  # hmm
        "event_class": "C0FFEEC0-FFEE-COFF-EECO-FFEEC0FFEEC1",
        "msg": message,
        "plc": LOG_DAEMON_HOST_NAME,
        "source": f"logging.aggregator/LogDaemon{source_suffix}",
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
    tasks: str = ""
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
    def description(self) -> str:
        """Text description for logging purposes."""
        info = [
            f"PLC at {self.address}",
        ]
        if self.host_name != self.address:
            info.append(f"({self.host_name})")
        if self.name != self.host_name and self.name:
            info.append(f"PLC {self.name!r}")
        if self.application_name != self.name and self.application_name:
            info.append(f"running application {self.application_name!r}")
        return " ".join(info)

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
                raise asyncio.TimeoutError() from None

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
            except asyncio.TimeoutError:
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

    async def update_device_info(
        self, circuit: AsyncioClientCircuit
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Update device information (project name, task names, etc.)

        Requires an active connection to the PLC via ads-async's
        AsyncioClientCircuit.

        Returns
        -------
        change_desc : str
            User-friendly description of the changes.
        changes : dict[str, Any]
            The individual changes.
        """
        try:
            device_info = await circuit.get_device_information()
            project_name = await get_or_fallback(circuit.get_project_name(), "")
            app_name = await get_or_fallback(circuit.get_app_name(), "")
            tasks = await get_or_fallback(circuit.get_task_names(), {})
        except (asyncio.TimeoutError, DisconnectedError) as ex:
            raise DisconnectedError(f"Unable to read device information: {ex}") from ex

        new_info = {
            "version": "{}.{}.{}".format(*device_info.version.as_tuple),
            "device_info_name": device_info.name,
            "project_name": project_name,
            "tasks": ", ".join(tasks.values()),
            "application_name": app_name,
            # Can also get like `stLibVersion_Tc3_Module` or for LCLS general, etc.
        }
        changes = {
            attr: (getattr(self, attr), value)
            for attr, value in new_info.items()
            if getattr(self, attr, None) != value
        }

        logger.info(
            "Updated device information of %s: %s",
            self.host_name,
            ", ".join(f"{attr} = {value!r}" for attr, value in new_info.items()),
        )

        if not changes:
            return "", {}

        def get_change_description(attr: str, old_value: Any, new_value: Any) -> str:
            attr = attr.replace("_", " ").capitalize()
            if old_value is None or old_value in ([], ""):
                return f"{attr} = {new_value!r}"
            return f"{attr} = {new_value!r} (was {old_value})"

        change_description = ", ".join(
            get_change_description(attr, old, new)
            for attr, (old, new) in changes.items()
        )
        logger.info("%s information updated: %s", self.name, change_description)
        for attr, (_, new) in changes.items():
            setattr(self, attr, new)

        return change_description, changes


class ClientLogger:
    """
    Per-PLC ads-async asyncio client-based logging.
    """

    #: PLC Information container for the target.
    plc: PlcInformation
    #: Time that the client was created.
    creation_time: float
    #: The Net ID the log daemon will report.
    our_net_id: str
    #: Add a filter to the following log handler if set:
    add_log_filter: bool
    #: Logging handler.
    handler: logging.Handler
    #: Add a route to the PLC if set.
    add_route: bool
    #: The ads-async client instance.
    client: Optional[AsyncioClientConnection]
    #: The ads-async client's circuit.
    circuit: Optional[AsyncioClientCircuit]
    #: The log task happening in the background.
    _log_task: Optional[asyncio.Task]
    #: Whether or not the client loop is running.
    running: bool

    def __init__(
        self,
        handler: logging.Handler,
        their_host: str,
        udp_queue: asyncio.Queue,
        their_net_id: Optional[str] = None,
        our_net_id: Optional[str] = None,
        add_log_filter: bool = True,
        add_route: bool = True,
        ldap_metadata: Optional[dict] = None,
    ):
        self.creation_time = time.monotonic()
        self.handler = handler
        self.add_log_filter = add_log_filter
        self.add_route = add_route
        self.our_net_id = our_net_id or LOG_DAEMON_NET_ID
        self.client = None
        self.circuit = None
        self.udp_queue = udp_queue
        self.ldap_metadata = dict(ldap_metadata or {})
        self.running = False
        self.plc = PlcInformation(
            net_id=their_net_id or f"{their_host}.1.1",
            address=their_host,
            host_name=self.ldap_metadata.get("host_name", their_host),
            ldap_metadata=dict(ldap_metadata or {}),
        )
        self._log_task = None

    async def _on_connection(
        self, client: AsyncioClientConnection, circuit: AsyncioClientCircuit
    ) -> None:
        """Run on initial connection to the PLC."""
        await self._update_device_info(
            circuit=circuit,
            timeout=2.0,
        )
        # Wait a bit for old notificationst to come in
        await asyncio.sleep(1.0)

    async def _start_logging(
        self, client: AsyncioClientConnection, circuit: AsyncioClientCircuit
    ) -> None:
        """Wrapper around ``_log_loop`` to catch exceptions."""
        try:
            await self._log_loop(client, circuit)
        except (DisconnectedError, asyncio.CancelledError) as ex:
            logger.warning(
                "Logging for %s exiting due to %s",
                self.plc.description,
                ex.__class__.__name__,
            )
        except Exception as ex:
            logger.exception(
                "Logging for %s exiting unexpectedly due to %s",
                self.plc.description,
                ex.__class__.__name__,
            )
            raise
        finally:
            self.running = False

    async def _log_loop(
        self, client: AsyncioClientConnection, circuit: AsyncioClientCircuit
    ) -> None:
        """Subscribe to PLC log messages and ship them to logstash."""
        await self.log(
            create_status_message(
                message=f"Logging daemon now monitoring {self.plc.description}",
                custom_json=self.plc.asdict(),
                source_detail="connectivity",
            )
        )

        # Prune any stale notifications from previous sessions:
        await circuit.prune_unknown_notifications()
        logger.info(
            "%s: Enabling the log system and waiting for messages...",
            self.plc.description,
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
                    self.plc.description,
                    sample,
                )

    async def _keepalive(
        self, client: AsyncioClientConnection, circuit: AsyncioClientCircuit
    ):
        """Keepalive loop for a PLC connection."""
        try:
            while self.running:
                await self._update_device_info(
                    circuit=circuit,
                    timeout=LOG_DAEMON_KEEPALIVE,
                )
                await asyncio.sleep(LOG_DAEMON_KEEPALIVE)
        except (asyncio.TimeoutError, DisconnectedError, asyncio.CancelledError) as ex:
            logger.warning(
                "Keepalive exiting for %s due to %s %s",
                self.plc.description,
                ex.__class__.__name__,
                ex,
            )
            raise
        except Exception as ex:
            logger.exception(
                "Logging keepalive for %s exiting unexpectedly due to %s",
                self.plc.description,
                ex.__class__.__name__,
            )
            raise
        finally:
            self.running = False

    async def run(self):
        """Connect to the PLC via ads-async and run the logging loop."""
        self.running = True
        if self.add_log_filter:
            # Filter the circuit-level messages:
            self.handler.addFilter(
                ads_async.log.AddressFilter(self.our_net_id, self.plc.net_id)
            )

        plc_info = await self.plc.update_service_information()
        logger.debug("Host: %s Got PLC info: %s", self.plc.description, plc_info)

        if self.add_route:
            await self._add_route()

        client = None
        log_task = None
        connection_initialized = False
        try:
            async with Client(
                self.plc.tcp_address_tuple, our_net_id=self.our_net_id
            ) as client:
                self.client = client
                async with client.get_circuit(self.plc.net_id) as circuit:
                    self.circuit = circuit

                    log_task = await self._on_connection(client, circuit)
                    connection_initialized = True
                    log_task = asyncio.create_task(self._start_logging(client, circuit))
                    self._log_task = log_task
                    await self._keepalive(client, circuit)
        except (asyncio.TimeoutError, DisconnectedError) as ex:
            logger.debug(
                "Disconnected from plc (%s): %s",
                ex.__class__.__name__,
                self.plc.description,
            )
            if connection_initialized:
                await self.log(
                    create_status_message(
                        message=(
                            f"PLC disconnected from logging daemon: "
                            f"{self.plc.description}"
                        ),
                        custom_json=self.plc.asdict(),
                        source_detail="connectivity",
                    )
                )
            else:
                await self.log(
                    create_status_message(
                        message=(
                            f"Unable to initialize logging for "
                            f"{self.plc.description}"
                        ),
                        custom_json=self.plc.asdict(),
                        source_detail="connectivity",
                    )
                )
        except asyncio.CancelledError:
            logger.debug("Task canceled for %s", self.plc.description)
        except Exception as ex:
            logger.exception(
                "Unexpected failure for %s: %s %s",
                self.plc.description,
                ex.__class__.__name__,
                ex,
            )
            raise
        finally:
            if log_task is not None:
                log_task.cancel()

                try:
                    await log_task
                except Exception:
                    ...

            self.client = None
            self.circuit = None
            self.running = False
            if client is not None:
                try:
                    await client.close()
                    await client.user_callback_executor.shutdown()
                except OSError:
                    # Actually disconnected; don't worry
                    ...
                except Exception:
                    logger.warning(
                        "Failed to close client for %s",
                        self.plc.description,
                        exc_info=True,
                    )

    async def _update_device_info(
        self,
        timeout: float = LOG_DAEMON_KEEPALIVE,
        circuit: Optional[AsyncioClientCircuit] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Update the device information and log any changes.
        """
        if circuit is None:
            circuit = self.circuit
            if circuit is None:
                return

        change_desc, changes = await asyncio.wait_for(
            self.plc.update_device_info(circuit),
            timeout=timeout,
        )
        if change_desc:
            await self.log(
                create_status_message(
                    message=(
                        f"PLC settings may have changed: {self.plc.name!r}: "
                        f"{change_desc}"
                    ),
                    custom_json=self.plc.asdict(),
                    source_detail="settings",
                )
            )
        return changes

    async def log(self, message: Dict[str, Any]):
        """Ship a message to logstash via the UDP queue."""
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
            logger.info("Added route to PLC %s", self.plc.description)
            return result

        logger.info("Adding route to PLC in background: %s", self.plc.description)
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
            self.plc.description,
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
            try:
                await log_task
            except Exception:
                ...
            self._log_task = None
