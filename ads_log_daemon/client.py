import asyncio
import json

import ads_async
from ads_async import structs
from ads_async.asyncio.client import AsyncioClient


def to_logstash(header: structs.AoEHeader,
                message: structs.AdsNotificationLogMessage) -> dict:
    custom_json = {
        "port_name": message.sender_name.decode('ascii'),
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
        "msg": message.message.decode('latin-1'),
        "source": "logging.aggregator/Translator",
        "event_type": 0,  # hmm
        "json": json.dumps(custom_json),
    }


async def test():
    ads_async.log.configure(level='DEBUG')

    async with AsyncioClient(
        ('localhost', 48898),
        our_net_id='172.21.148.164.1.1'
    ) as client:
        circuit = client.get_circuit('172.21.148.227.1.1')
        device_info = await circuit.get_device_information()
        circuit.log.info('Device info: %s', device_info)
        project_name = await circuit.get_project_name()
        circuit.log.info('Project name: %s', project_name)
        app_name = await circuit.get_app_name()
        circuit.log.info('Application name: %s', app_name)
        task_names = await circuit.get_task_names()
        circuit.log.info('Task names: %s', task_names)

        # Give some time for initial notifications, and prune any stale
        # ones from previous sessions:
        await asyncio.sleep(1.0)
        await circuit.prune_unknown_notifications()
        async for header, _, sample in circuit.enable_log_system():
            try:
                message = sample.as_log_message()
            except Exception:
                circuit.log.exception('Got a bad log message sample? %s',
                                      sample)
                continue

            circuit.log.info(
                "Log message %s ==> %s", message,
                to_logstash(header, message)
            )


if __name__ == '__main__':
    value = asyncio.run(test(), debug=True)
