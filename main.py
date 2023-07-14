import base64
import pprint

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


def uleb128_decode(b: bytes | bytearray) -> int:
    r = 0
    for i, e in enumerate(b):
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
    packet.append(length)
    packet.extend(payload)
    packet.append(check_summ)
    return bytes(packet)


def decode_cmd_body(cmd_body: bytes | bytearray, dev_type: int, cmd: int) -> dict:
    data = dict()
    if dev_type == 6:
        if cmd == 2:
            data['dev_name'] = cmd_body[1:].decode('ascii')
        elif cmd == 6:
            timestamp = uleb128_decode(cmd_body)
            data['timestamp'] = timestamp
    elif dev_type == 4:
        if cmd == 2:
            data['dev_name'] = cmd_body[1:].decode('ascii')
    elif dev_type == 3:
        if cmd == 2:
            length = cmd_body[0]
            data['dev_name'] = cmd_body[1:length + 1].decode('ascii')
            dev_names = []
            i = length + 2
            for _ in range(cmd_body[i - 1]):
                length = cmd_body[i]
                new_name = cmd_body[i+1:i+1+length].decode('ascii')
                dev_names.append(new_name)
                i += length + 1
            data['dev_names'] = dev_names
    return data


def decode_payload(payload: bytes) -> dict:
    data = dict()
    src = bytearray()
    dst = bytearray()
    serial = bytearray()
    i = 0
    while payload[i] & 0x80:
        src.append(payload[i])
        i += 1
    src.append(payload[i])
    i += 1
    while payload[i] & 0x80:
        dst.append(payload[i])
        i += 1
    dst.append(payload[i])
    i += 1
    while payload[i] & 0x80:
        serial.append(payload[i])
        i += 1
    serial.append(payload[i])
    i += 1
    data['src'] = uleb128_decode(src)
    data['dst'] = uleb128_decode(dst)
    data['serial'] = uleb128_decode(serial)
    data['dev_type'] = payload[i]
    i += 1
    data['cmd'] = payload[i]
    i += 1
    cmd_body_bin = payload[i:]
    data['cmd_body'] = decode_cmd_body(cmd_body_bin, data['dev_type'], data['cmd'])
    return data


def decode_packet(packet: bytes) -> dict:
    data = dict()
    length = packet[0]
    data['length'] = length
    bin_payload: bytes = packet[1:1+length]
    payload = decode_payload(bin_payload)
    data['payload'] = payload
    data['crc8'] = packet[length + 1]
    return data


def decode_packets(packets: bytes) -> list[dict]:
    decoded_packets = []
    i = 0
    while i < len(packets):
        length = packets[i]
        new_pack = decode_packet(packets[i:i+length+2])
        decoded_packets.append(new_pack)
        i += length + 2
    return decoded_packets


def main() -> None:
    # my_cmd_body = make_cmd_body(1, dev_name='kabanchik')
    # my_packet = make_packet(make_payload(819, 16383, 1, 1, 1, my_cmd_body))
    # bcode = base64.urlsafe_b64encode(my_packet).decode('ascii').rstrip('=')
    # print(bcode)
    #
    # r = requests.post("http://localhost:9998", data=bcode)
    # print(r.content)
    # decoded_content = base64.urlsafe_b64decode(r.content + b'==')
    # pprint.pprint(decode_packets(decoded_content))
    # r = requests.post("http://localhost:9998")
    # decoded_content = base64.urlsafe_b64decode(r.content + b'==')
    # pprint.pprint(decode_packets(decoded_content))
    decode_string = input().encode('ascii')
    decoded_content = base64.urlsafe_b64decode(decode_string + b'==')
    pprint.pprint(decode_packets(decoded_content))


if __name__ == "__main__":
    main()
