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
from typing import Any, Dict, List, Set

import ads_async

from .client import ClientLogger
from .config import LOG_DAEMON_RECONNECT_PERIOD, LOG_DAEMON_SEARCH_PERIOD
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


class LdapLogger:
    handler: logging.Handler
    ld: LDAPHelper
    host_info: Dict[str, Any]
    tasks: Dict[str, asyncio.Task]
    udp_queue: asyncio.Queue
    recently_removed_hosts: Set[str]
    ldap_update_deadline: float

    def __init__(self, handler: logging.Handler):
        self.handler = handler
        self.ld = LDAPHelper()
        self.host_info = {}
        self.host_to_task = {}
        self.recently_removed_hosts = set()
        self.ldap_update_deadline = time.monotonic()

    def describe_host(self, host: str):
        try:
            info = self.host_info[host]
        except KeyError:
            return host

        return (
            "host={host_name} ({ip_address}/{mac}) {desc!r} @ {location!r}"
            "".format(**info)
        )

    async def _show_connection_status_loop(self):
        while True:
            hosts = ", ".join(list(self.host_to_task))
            logger.info(
                "PLC hosts being monitored: num=%d %s", len(self.host_to_task), hosts
            )
            try:
                await asyncio.sleep(120)
            except asyncio.CancelledError:
                break

    async def _client_handler(self, host: str):
        client = None
        try:
            ldap_metadata = self.host_info[host]
            client = ClientLogger(
                self.handler,
                ldap_metadata["ip_address"],
                ldap_metadata=ldap_metadata,
                udp_queue=self.udp_queue,
            )
            await client.run()
        except Exception as ex:
            logger.exception(
                "Client handler for %s exited unexpectedly: %s %s",
                host,
                ex.__class__.__name__,
                ex,
            )
        finally:
            logger.info("Cleaning up client handler for %s", host)
            self.host_to_task.pop(host, None)
            if client is not None:
                logger.info(
                    "Removing dead task for %s",
                    self.describe_host(host),
                )
                await client.stop()

    async def _update_ldap(self):
        if time.monotonic() < self.ldap_update_deadline:
            return

        logger.info("Looking for new hosts with LDAP...")
        self.ldap_update_deadline = time.monotonic() + LOG_DAEMON_SEARCH_PERIOD
        try:
            self.recently_removed_hosts, _ = await self.ld.update_hosts_async()
        except Exception:
            logger.exception(
                "Failed to update LDAP hosts. Waiting for twice the "
                "normal search period (= %s seconds).",
                LOG_DAEMON_SEARCH_PERIOD * 2,
            )
            # Make the deadline later
            self.ldap_update_deadline = time.monotonic() + LOG_DAEMON_SEARCH_PERIOD * 2
            # Re-initialize the LDAP helper
            self.ld = self.ld.duplicate()
        else:
            self.host_info.clear()
            self.host_info.update(self.ld.hosts)
            for host in self.recently_removed_hosts:
                self.host_info.pop(host, None)
                task = self.host_to_task.pop(host, None)
                if task is not None:
                    logger.info(
                        "Host %s was removed from LDAP; canceling its task", host
                    )
                    task.cancel()
                    try:
                        await task
                    except Exception:
                        ...

    async def run(self):
        """Run the daemon using the configured LDAP settings to search for PLCs."""
        # Remember: the queue has to be created in a coroutine associated with
        # the event loop.
        self.udp_queue = asyncio.Queue()
        local_tasks = [
            asyncio.create_task(
                udp_transport_loop(self.udp_queue),
                name="queue_task",
            ),
            asyncio.create_task(
                self._show_connection_status_loop(),
                name="connection_status",
            ),
        ]
        try:
            while True:
                await self._update_ldap()
                missing_tasks = set(self.host_info) - set(self.host_to_task)

                for host in missing_tasks:
                    logger.info("New host to monitor: %s", self.describe_host(host))
                    self.host_to_task[host] = asyncio.create_task(
                        self._client_handler(host), name=f"log_{host}"
                    )

                try:
                    for coro in asyncio.as_completed(
                        list(self.host_to_task.values()),
                        timeout=LOG_DAEMON_RECONNECT_PERIOD,
                    ):
                        try:
                            await coro
                        except asyncio.TimeoutError:
                            raise
                    # If the above completes successfully, make sure we wait
                    await asyncio.sleep(LOG_DAEMON_SEARCH_PERIOD)
                except asyncio.TimeoutError:
                    ...

        finally:
            logger.info("LdapLogger exiting; cleaning up tasks...")
            for task in local_tasks:
                if task is not None:
                    task.cancel()
                    try:
                        await task
                    except Exception:
                        ...


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
        ldap_logger = LdapLogger(handler)
        to_run = ldap_logger.run()
    else:
        to_run = main_manual(handler, args.host)
    return asyncio.run(to_run, debug=True)


if __name__ == "__main__":
    value = main()  # noqa
