import base64
import pprint
import sys

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


def make_packet(src: int, dst: int, serial: int, dev_type: int, cmd: int, **kwargs) -> bytes:
    packet = bytearray()
    payload = make_payload(src, dst, serial, dev_type, cmd, kwargs)

    length = len(payload)
    check_summ = crc8(payload)
    packet.append(length)
    packet.extend(payload)
    packet.append(check_summ)
    return packet
    # return base64.urlsafe_b64encode(packet).decode('ascii').rstrip('=')


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
        elif cmd == 4 or cmd == 5:
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
    data['real_crc8'] = crc8(bin_payload)
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
    # decode_string = input().encode('ascii')
    # decoded_content = base64.urlsafe_b64decode(decode_string + b'==')
    # pprint.pprint(decode_packets(decoded_content))
    #
    # return

    # url = sys.argv[1]
    # src = int(sys.argv[2], 16)

    url = "http://localhost:9998"
    src = 124

    serial = 1
    who_is_here = make_packet(src, 0x3fff, serial, 1, 1, dev_name="HUB01")
    serial += 1

    r = requests.post(url, base64.urlsafe_b64encode(who_is_here).decode('ascii').rstrip('='))
    resp = base64.urlsafe_b64decode(r.content + b'==')
    resp_packets = decode_packets(resp)

    start_time = resp_packets[0]['payload']['cmd_body']['timestamp']
    current_time = start_time

    devs = dict()
    name_by_addr = dict()

    while True:
        start = 0
        if len(resp_packets) > 0 and resp_packets[0]['payload']['cmd'] == 6 and\
                resp_packets[0]['crc8'] == resp_packets[0]['real_crc8']:
            current_time = resp_packets[0]['payload']['cmd_body']['timestamp']
            start = 1
        addrs = list(name_by_addr.keys())
        for addr in addrs:
            dev_name = name_by_addr[addr]
            if current_time - devs[dev_name].get('get_time', current_time) > 300:
                name_by_addr.pop(addr)
                devs.pop(dev_name)
        send_packets = bytearray()
        for packet in resp_packets[start:]:
            if packet['crc8'] != packet['real_crc8']:
                continue
            # IAMHERE
            elif packet['payload']['cmd'] == 2:
                if current_time - start_time > 300:
                    continue
                addres = packet['payload']['src']
                dev_type = packet['payload']['dev_type']
                dev_name = packet['payload']['cmd_body']['dev_name']
                name_by_addr[addres] = dev_name
                devs[dev_name] = dict()
                devs[dev_name]['addres'] = addres
                devs[dev_name]['type'] = dev_type
                if dev_type == 2 or dev_type == 3:
                    devs[dev_name]['props'] = packet['payload']['cmd_body']['dev_props']
                if dev_type != 6:
                    get_status = make_packet(src, addres, serial, dev_type, 3)
                    serial += 1
                    send_packets.extend(get_status)
                    devs[dev_name]['get_time'] = current_time
            # STATUS
            elif packet['payload']['cmd'] == 4:
                if packet['payload']['src'] not in name_by_addr.keys():
                    continue
                addr = packet['payload']['src']
                dev_name = name_by_addr[addr]
                dev_type = packet['payload']['dev_type']
                devs[dev_name].pop('get_time', None)
                if dev_type == 2:
                    devs[dev_name]['status'] = packet['payload']['cmd_body']['values']
                elif dev_type == 3:
                    devs[dev_name]['status'] = packet['payload']['cmd_body']['value']
                    for send_name in devs[dev_name]['props']['dev_names']:
                        devs[send_name]['get_time'] = current_time
                        send_addr = devs[send_name]['addres']
                        send_type = devs[send_name]['type']
                        set_status = make_packet(src, send_addr, serial, send_type, 5, value=devs[dev_name]['status'])
                        serial += 1
                        send_packets.extend(set_status)
                elif dev_type == 4 or dev_type == 5:
                    devs[dev_name]['status'] = packet['payload']['cmd_body']['value']

        try:
            r = requests.post(url, base64.urlsafe_b64encode(send_packets).decode('ascii').rstrip('='))
            assert r.status_code == 200 or r.status_code == 204
        except requests.RequestException:
            print('http error')
            sys.exit(99)
        except AssertionError:
            pprint.pprint(decode_packets(send_packets))
            print(base64.urlsafe_b64encode(send_packets).decode('ascii').rstrip('='))
            print('wrong status code')
            sys.exit(99)

        if r.status_code == 204:
            sys.exit(0)

        try:
            resp = base64.urlsafe_b64decode(r.content + b'==')
            resp_packets = decode_packets(resp)
        except IndexError:
            continue


if __name__ == "__main__":
    main()
