===============================
ads-log-daemon
===============================

.. image:: https://img.shields.io/travis/pcdshub/ads-log-daemon.svg
        :target: https://travis-ci.org/pcdshub/ads-log-daemon

.. image:: https://img.shields.io/pypi/v/ads-log-daemon.svg
        :target: https://pypi.python.org/pypi/ads-log-daemon


Daemon for translating TwinCAT ADS Logger messages to JSON for interpretation by [pcds-]logstash.

`Documentation <https://pcdshub.github.io/ads-log-daemon/>`_

Requirements
------------

* Python 3.7+
* `ads-async <https://github.com/pcdshub/ads-async>`_

Installation
------------
::

  $ python -m pip install .


Running the Tests
-----------------
::

  $ pytest -vv
