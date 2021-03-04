import asyncio
import json
import logging
import os
import sys
from typing import Optional

import ads_async
from ads_async import constants, structs
from ads_async.asyncio.client import Client
from ads_async.bin.info import get_plc_info
from ads_async.bin.route import add_route_to_plc
from ads_async.exceptions import RequestFailedError

LOG_DAEMON_HOST = os.environ.get("LOG_DAEMON_NET_ID", "172.21.32.90")
LOG_DAEMON_NET_ID = os.environ.get("LOG_DAEMON_NET_ID", f"{LOG_DAEMON_HOST}.1.1")
LOG_DAEMON_ROUTE_NAME = os.environ.get("LOG_DAEMON_ROUTE_NAME", "ads-log-daemon")
logger = logging.getLogger(__name__)


def to_logstash(
    header: structs.AoEHeader, message: structs.AdsNotificationLogMessage
) -> dict:
    custom_json = {
        "port_name": message.sender_name.decode("ascii"),
        "ams_port": message.ams_port,
        "source": repr(header.source),
        "identifier": message.unknown,
    }

    # From:
    # AdsNotificationLogMessage(timestamp=datetime.datetime,
    #                           unknown=84, ams_port=500,
    #                           sender_name=b'TCNC',
    #                           message_length=114, message=b'\'Axis
    #                           1\' (Axis-ID: 1): The axis needs the
    #                           "Feed Forward Permission" for forward
    #                           positioning (error-code: 0x4358) !')
    # To:
    # (f'{"schema":"twincat-event-0","ts":{twincat_now},"plc":"LogTest",'
    #   '"severity":4,"id":0,'
    #   '"event_class":"C0FFEEC0-FFEE-COFF-EECO-FFEEC0FFEEC0",'
    #   '"msg":"Critical (Log system test.)",'
    #   '"source":"pcds_logstash.testing.fbLogger/Debug",'
    #   '"event_type":3,"json":"{}"}'
    #   ),
    return {
        "schema": "twincat-event-0",
        "ts": message.timestamp.timestamp(),
        "severity": 0,  # hmm
        "id": 0,  # hmm
        "event_class": "C0FFEEC0-FFEE-COFF-EECO-FFEEC0FFEEC0",
        "msg": message.message.decode("latin-1"),
        "source": "logging.aggregator/PythonLogDaemon",
        "event_type": 0,  # hmm
        "json": json.dumps(custom_json),
    }


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
                "name": plc_info["plc_name"],
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
            async for header, _, sample in circuit.enable_log_system():
                try:
                    message = sample.as_log_message()
                except Exception:
                    logger.exception("Got a bad log message sample? %s", sample)
                    continue

                logger.info(
                    "Log message %s ==> %s", message, to_logstash(header, message)
                )


if __name__ == "__main__":
    logging.basicConfig(format=ads_async.log.PLAIN_LOG_FORMAT, level="INFO")
    handler = ads_async.log.configure(level="INFO")
    plc_host = sys.argv[1]
    value = asyncio.run(client_loop(plc_host), debug=True)
