from __future__ import annotations

import asyncio
import json
import logging

from .config import LOG_DAEMON_ENCODING, LOG_DAEMON_TARGET_HOST, LOG_DAEMON_TARGET_PORT

logger = logging.getLogger(__name__)


class _UdpProtocol(asyncio.DatagramProtocol):
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


async def udp_transport_loop(
    queue: asyncio.Queue,
    host: str = LOG_DAEMON_TARGET_HOST,
    port: int = LOG_DAEMON_TARGET_PORT,
) -> None:
    """Ship messages from the queue to logstash at ``(host, port)`` over UDP."""
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
