"""
Daemon for translating TwinCAT ADS Logger messages to JSON for interpretation
by [pcds-]logstash.

Environment variables
=====================

Host and AMS Net ID of the daemon:
    LOG_DAEMON_HOST
    LOG_DAEMON_NET_ID (defaults to host.1.1)

The host name to report for daemon status messages:
    LOG_DAEMON_HOST_NAME (defaults to the system hostname)

Route name to add to PLC:
    LOG_DAEMON_ROUTE_NAME (defaults to "ads-log-daemon")

Encoding of messages from the PLC:
    LOG_DAEMON_SOURCE_ENCODING (defaults to "latin-1")

Logstash target host and port:
    LOG_DAEMON_TARGET_HOST
    LOG_DAEMON_TARGET_PORT

Encoding for the generated logstash JSON messages:
    LOG_DAEMON_ENCODING (defaults to "utf-8")

Reach out to a PLC by its service port at this rate:
    LOG_DAEMON_INFO_PERIOD (defaults to 60 seconds)
    LOG_DAEMON_KEEPALIVE (defaults to 120 seconds)

LDAP settings:
    LOG_DAEMON_SEARCH_PERIOD (defaults to 900 seconds or 15 minutes)
    LOG_DAEMON_HOST_PREFIXES - comma-delimited hostname prefixes
    LOG_DAEMON_LDAP_SERVER
    LOG_DAEMON_LDAP_SEARCH_BASE


Clock misconfiguration thresholds:
Are we within, e.g., a minute of what this machine's time shows?  Check for
clock skew/ missing NTP settings/etc
    LOG_DAEMON_TIMESTAMP_THRESHOLD - defaults to 60 seconds
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import time
from typing import List

import ads_async

from .client import ClientLogger
from .config import LOG_DAEMON_SEARCH_PERIOD
from .ldap_helper import LDAPHelper
from .logstash import udp_transport_loop

DESCRIPTION = __doc__


logger = logging.getLogger(__name__)


async def main_manual(handler: logging.Handler, client_addresses: List[str]):
    """Run the daemon with manually-specified list of client addresses."""
    if len(client_addresses) == 0:
        logger.error("No client addresses given; exiting")
        return

    udp_queue = asyncio.Queue()
    clients = [
        ClientLogger(handler, addr, udp_queue=udp_queue) for addr in client_addresses
    ]
    tasks = [asyncio.create_task(client.run()) for client in clients]
    tasks.append(asyncio.create_task(udp_transport_loop(udp_queue)))
    await asyncio.gather(*tasks)


async def main_ldap(handler: logging.Handler):
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

    async def prune_tasks():
        for host, task in list(tasks.items()):
            client = logger_clients.get(host, None)
            if task.done():
                logger.info("Removing dead task for %s", describe_host(host))
                tasks.pop(host)
                if client is not None:
                    logger_clients.pop(host)
                    await client.stop()
            elif client is not None and not client.running:
                if (time.monotonic() - client.creation_time) > 10:
                    logger.info("Client no longer running for %s", describe_host(host))
                    task = tasks.pop(host)
                    if task is not None:
                        task.cancel()
                    logger_clients.pop(host)
                    await client.stop()

    logger_clients = {}

    udp_queue = asyncio.Queue()
    queue_task = asyncio.create_task(udp_transport_loop(udp_queue))

    try:
        while True:
            logger.info("Looking for new hosts with LDAP...")
            try:
                removed_hosts, _ = ld.update_hosts()
            except Exception:
                logger.exception(
                    "Failed to update LDAP hosts. Waiting for twice the "
                    "normal search period (= %s seconds).",
                    LOG_DAEMON_SEARCH_PERIOD * 2,
                )
                await asyncio.sleep(LOG_DAEMON_SEARCH_PERIOD * 2)
                # Re-initialize the LDAP helper
                ld = ld.duplicate()
                continue

            for host in removed_hosts:
                task = tasks.pop(host, None)
                if task is not None:
                    task.cancel()

            await asyncio.sleep(1.0)
            missing_tasks = set(ld.hosts) - set(tasks)

            for host in missing_tasks:
                info = ld.hosts[host]
                logger.info("New host: %s", describe_host(host))
                client = ClientLogger(
                    handler,
                    info["ip_address"],
                    ldap_metadata=info,
                    udp_queue=udp_queue,
                )
                logger_clients[host] = client
                tasks[host] = asyncio.create_task(client.run(), name=f"log_{host}")

            try:
                for coro in asyncio.as_completed(
                    set(tasks.values()), timeout=LOG_DAEMON_SEARCH_PERIOD
                ):
                    try:
                        await coro
                    except asyncio.TimeoutError:
                        raise
                    except Exception:
                        await prune_tasks()
            except asyncio.TimeoutError:
                ...

            await asyncio.sleep(0.5)
            await prune_tasks()
            await asyncio.sleep(0.5)
    finally:
        if queue_task is not None:
            queue_task.cancel()


def build_argparser():
    parser = argparse.ArgumentParser(
        prog="ads-log-daemon",
        description=DESCRIPTION,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    from . import __version__

    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=__version__,
        help="Show the version number and exit.",
    )

    parser.add_argument(
        "--ldap",
        action="store_true",
        help="Set LDAP mode",
    )

    parser.add_argument(
        "host",
        nargs="*",
        help="Communicate with these specific PLC hosts",
    )

    return parser


def main():
    logging.basicConfig(format=ads_async.log.PLAIN_LOG_FORMAT, level="INFO")
    handler = ads_async.log.configure(level="INFO")
    parser = build_argparser()
    args = parser.parse_args()
    logging.getLogger("ads_async.bin.utils").setLevel(logging.WARNING)
    if args.ldap:
        to_run = main_ldap(handler)
    else:
        to_run = main_manual(handler, args.host)
    return asyncio.run(to_run, debug=True)


if __name__ == "__main__":
    value = main()  # noqa
