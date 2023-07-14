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


def make_cmd_body(cmd: int, kwargs: dict) -> bytearray:
    b = bytearray()
    # WHOISHERE, IAMHERE
    if cmd == 1 or cmd == 2:
        b.append(len(kwargs['dev_name']))
        dev_name = kwargs['dev_name'].encode()
        b.extend(dev_name)
    # GETSTATUS
    elif cmd == 3:
        pass
    # SETSTATUS
    elif cmd == 5:
        b.append(kwargs['value'])
    return b


def make_payload(src: int, dst: int, serial: int, dev_type: int, cmd: int, kwargs: dict) -> bytearray:
    payload = bytearray()
    cmd_body = make_cmd_body(cmd, kwargs)

    payload.extend(uleb128_encode(src))
    payload.extend(uleb128_encode(dst))
    payload.extend(uleb128_encode(serial))

    payload.append(dev_type)
    payload.append(cmd)
    payload.extend(cmd_body)
    return payload


def make_packet(src: int, dst: int, serial: int, dev_type: int, cmd: int, **kwargs) -> str:
    packet = bytearray()
    payload = make_payload(src, dst, serial, dev_type, cmd, kwargs)

    length = len(payload)
    check_summ = crc8(payload)
    packet.append(length)
    packet.extend(payload)
    packet.append(check_summ)
    return base64.urlsafe_b64encode(packet).decode('ascii').rstrip('=')


def decode_cmd_body(cmd_body: bytes | bytearray, dev_type: int, cmd: int) -> dict:
    data = dict()

    # EnvSensor
    if dev_type == 2:
        # WHOISHERE, IAMHERE
        if cmd == 1 or cmd == 2:
            length = cmd_body[0]
            data['dev_name'] = cmd_body[1:length + 1].decode('ascii')
            dev_props = dict()
            i = length + 1
            dev_props['sensors'] = cmd_body[i]
            i += 1
            array_len = cmd_body[i]
            triggers: list[dict] = []
            i += 1
            for _ in range(array_len):
                new_trigger = dict()
                new_trigger['op'] = cmd_body[i]
                bin_value = bytearray()
                while True:
                    i += 1
                    bin_value.append(cmd_body[i])
                    if not cmd_body[i] & 0x80:
                        break
                new_trigger['value'] = uleb128_decode(bin_value)
                i += 1
                name_len = cmd_body[i]
                new_trigger['name'] = cmd_body[i+1:i+1+name_len].decode('ascii')
                i += 1 + name_len
                triggers.append(new_trigger)
            dev_props['triggers'] = triggers
            data['dev_props'] = dev_props

        # STATUS
        elif cmd == 4:
            values = []
            values_len = cmd_body[0]
            i = 0
            for _ in range(values_len):
                bin_value = bytearray()
                while True:
                    i += 1
                    bin_value.append(cmd_body[i])
                    if not cmd_body[i] & 0x80:
                        break
                values.append(uleb128_decode(bin_value))
            data['values'] = values

    # Clock
    if dev_type == 6:
        # WHOISHERE, IAMHERE
        if cmd == 2:
            data['dev_name'] = cmd_body[1:].decode('ascii')
        # TICK
        elif cmd == 6:
            timestamp = uleb128_decode(cmd_body)
            data['timestamp'] = timestamp

    # Lamp and Socket
    elif dev_type == 4 or dev_type == 5:
        # WHOISHERE, IAMHERE
        if cmd == 2 or cmd == 1:
            data['dev_name'] = cmd_body[1:].decode('ascii')
        # STATUS
        elif cmd == 4:
            data['value'] = cmd_body[0]

    # Switch
    elif dev_type == 3:
        # WHOISHERE, IAMHERE
        if cmd == 1 or cmd == 2:
            length = cmd_body[0]
            data['dev_name'] = cmd_body[1:length + 1].decode('ascii')
            dev_names = []
            i = length + 2
            for _ in range(cmd_body[i - 1]):
                length = cmd_body[i]
                new_name = cmd_body[i+1:i+1+length].decode('ascii')
                dev_names.append(new_name)
                i += length + 1
            data['dev_props'] = dict()
            data['dev_props']['dev_names'] = dev_names
        # STATUS
        elif cmd == 4:
            data['value'] = cmd_body[0]

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
    new_packet = make_packet(1, 5, 20, 5, 5, value=1)
    print(new_packet)

    # decode_string = input().encode('ascii')
    # decoded_content = base64.urlsafe_b64decode(decode_string + b'==')
    # pprint.pprint(decode_packets(decoded_content))


if __name__ == "__main__":
    main()
