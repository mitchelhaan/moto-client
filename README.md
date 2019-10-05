# moto-client
Motorola Surfboard Modem web client

Developed to help collect downstream/upstream channel statistics from my modem.
This modem (MB8600) uses a modified version of [HNAP](https://en.wikipedia.org/wiki/Home_Network_Administration_Protocol) for communication.

## Tested on
- Motorola Surfboard MB8600 (sw ver. 8600-18.2.12)

## Example Usage
```sh
$ python -i moto_client.py
connected
>>> c.connection_info()
{'MotoConnSystemUpTime': '32 days 08h:47m:08s', 'MotoConnNetworkAccess': 'Allowed'}
>>> c.downstream_info()
[{'Channel': '1', 'Status': 'Locked', 'Modulation': 'QAM256', ...
```
