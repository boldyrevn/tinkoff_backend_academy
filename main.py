import base64

import requests


def crc8(b: bytes) -> int:
    generator = 0x1d
    crc = 0
    for byte in b:
        crc ^= byte
        for i in range(8):
            if (crc & 0x80) != 0:
                crc = ((crc << 1) ^ generator) & 0xff
            else:
                crc <<= 1
    return crc


def uleb128_encode(n: int) -> bytes:
    assert n >= 0
    r = []
    while True:
        byte = n & 0x7f
        n >>= 7
        if n == 0:
            r.append(byte)
            return bytes(r)
        r.append(0x80 | byte)


def uleb128_decode(b: bytes) -> int:
    r = 0
    for i, e in enumerate(bytes):
        r += (e & 0x7f) << (i * 7)
    return r


def make_cmd_body(cmd: int, **kwargs) -> bytes:
    if cmd == 6:
        timestamp = uleb128_encode(kwargs['timestamp'])
        return timestamp
    elif cmd == 1:
        b = [len(kwargs['dev_name'])]
        dev_name = kwargs['dev_name'].encode()
        b.extend(dev_name)
        return bytes(b)


def make_payload(src: int, dst: int, serial: int, dev_type: int, cmd: int, cmd_body: bytes) -> bytes:
    payload = []

    payload.extend(uleb128_encode(src))
    payload.extend(uleb128_encode(dst))
    payload.extend(uleb128_encode(serial))

    payload.append(dev_type)
    payload.append(cmd)
    payload.extend(cmd_body)
    return bytes(payload)


def make_packet(payload: bytes) -> bytes:
    packet = []
    length = len(payload)
    check_summ = crc8(payload)
    print(check_summ)
    packet.append(length)
    packet.extend(payload)
    packet.append(check_summ)
    print(len(packet))
    return bytes(packet)


my_cmd_body = make_cmd_body(1, dev_name='kabanchik')
my_packet = make_packet(make_payload(819, 16383, 1, 1, 1, my_cmd_body))
bcode = base64.urlsafe_b64encode(my_packet).decode('ascii').rstrip('=')
print(bcode)

