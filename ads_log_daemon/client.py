import asyncio
import datetime
import json
import logging
import os
import sys
import time
from typing import Optional

import ads_async
from ads_async import constants, structs
from ads_async.asyncio.client import Client
from ads_async.bin.info import get_plc_info
from ads_async.bin.route import add_route_to_plc
from ads_async.exceptions import RequestFailedError

# Host and AMS Net ID of the daemon:
LOG_DAEMON_HOST = os.environ.get("LOG_DAEMON_NET_ID", "172.21.32.90")
LOG_DAEMON_NET_ID = os.environ.get("LOG_DAEMON_NET_ID", f"{LOG_DAEMON_HOST}.1.1")

# Route name to add to PLC:
LOG_DAEMON_ROUTE_NAME = os.environ.get("LOG_DAEMON_ROUTE_NAME", "ads-log-daemon")
# Encoding of messages from the PLC:
LOG_DAEMON_SOURCE_ENCODING = os.environ.get("LOG_DAEMON_SOURCE_ENCODING", "latin-1")

# Logstash target host and port:
LOG_DAEMON_TARGET_HOST = os.environ.get("LOG_DAEMON_TARGET_HOST", "ctl-logdev01")
LOG_DAEMON_TARGET_PORT = int(os.environ.get("LOG_DAEMON_TARGET_PORT", 54322))
# Encoding for the generated logstash JSON messages:
LOG_DAEMON_ENCODING = os.environ.get("LOG_DAEMON_ENCODING", "utf-8")

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
            logger.warning("Failed to send message: %s", ex)
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
    header: structs.AoEHeader,
    message: structs.AdsNotificationLogMessage,
    *,
    custom_message: Optional[str] = None,
    use_system_time: bool = False,
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
    msg = custom_message or message.message.decode(LOG_DAEMON_SOURCE_ENCODING).rstrip(
        "\x00"
    )
    return {
        "schema": "twincat-event-0",
        "ts": time.time() if use_system_time else message.timestamp.timestamp(),
        "severity": 0,  # hmm
        "id": 0,  # hmm
        "event_class": "C0FFEEC0-FFEE-COFF-EECO-FFEEC0FFEEC0",
        "msg": msg,
        "source": "logging.aggregator/PythonLogDaemon",
        "event_type": 3,  # 3=message_sent
        "json": json.dumps(custom_json),
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


async def client_loop(
    their_host: str,
    their_net_id: Optional[str] = None,
    our_net_id: Optional[str] = None,
    add_log_filter: bool = True,
    add_route: bool = True,
):
    our_net_id = our_net_id or LOG_DAEMON_NET_ID
    their_net_id = their_net_id or f"{their_host}.1.1"

    if add_log_filter:
        # Filter the circuit-level messages:
        handler.addFilter(ads_async.log.AddressFilter(our_net_id, their_net_id))

    plc_info = next(get_plc_info(their_host))
    logger.debug("Host: %s Got PLC info: %s", their_host, plc_info)
    if plc_info["source_net_id"] != their_net_id:
        logger.warning(
            "PLC reports Net ID: %s Configured Net ID: %s; using PLC-reported Net ID.",
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
        logger.info("Added route to PLC %s", their_host)

    udp_queue = asyncio.Queue()
    asyncio.create_task(
        udp_transport_loop(udp_queue, LOG_DAEMON_TARGET_HOST, LOG_DAEMON_TARGET_PORT)
    )

    async with Client(
        (their_host, constants.ADS_TCP_SERVER_PORT), our_net_id=our_net_id
    ) as client:
        async with client.get_circuit(their_net_id) as circuit:
            device_info = await circuit.get_device_information()
            project_name = await get_or_fallback(circuit.get_project_name(), "")
            app_name = await get_or_fallback(circuit.get_app_name(), "")
            task_names = await get_or_fallback(circuit.get_task_names(), [])

            logger.info("Service PLC info: %s", plc_info)
            logger.info(
                "PLC Device info: %s (%s)", device_info.version, device_info.name
            )
            # Project name such as "Project1"
            logger.info("Project name: %r", project_name)
            # Application name such as "Port_851"
            logger.info("Application name: %r", app_name)
            # Task names such as ["MAIN_PlcTask", ...]
            logger.info("Task names: %s", task_names)

            plc_identifier = {
                "net_id": plc_info["source_net_id"],
                "address": their_host,
                "plc_name": plc_info["plc_name"],
                "version": "{}.{}.{}".format(*device_info.version.as_tuple),
                "device_info_name": device_info.name,
                "project_name": project_name,
                "task_names": task_names,
                # Can also get like `stLibVersion_Tc3_Module` or for LCLS general, etc.
            }
            logger.info("PLC identifier: %s", plc_identifier)

            # Give some time for initial notifications, and prune any stale
            # ones from previous sessions:
            await asyncio.sleep(1.0)
            await circuit.prune_unknown_notifications()
            logger.info("Enabling the log system and waiting for messages...")
            clock_incorrect = None
            async for header, _, sample in circuit.enable_log_system():
                try:
                    message = sample.as_log_message()
                except Exception:
                    logger.exception("Got a bad log message sample? %s", sample)
                    continue

                logger.info(
                    "Log message %s ==> %s", message, to_logstash(header, message)
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
                                header,
                                message,
                                use_system_time=True,
                                custom_message=custom_msg,
                            )
                        )

                await udp_queue.put(
                    to_logstash(header, message, use_system_time=clock_incorrect)
                )


if __name__ == "__main__":
    logging.basicConfig(format=ads_async.log.PLAIN_LOG_FORMAT, level="INFO")
    handler = ads_async.log.configure(level="INFO")
    plc_host = sys.argv[1]
    value = asyncio.run(client_loop(plc_host), debug=True)
