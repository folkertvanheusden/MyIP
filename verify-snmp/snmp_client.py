#! /usr/bin/python3

class snmp_client:
    def __init__(self):
        pass

    @staticmethod
    def make_snmp_BER(type_: int, data: bytes):
        assert type_ >= 0x00 and type_ <= 0xff
        assert len(data) <= 256

        for d in data:
            assert d >= 0x00 and d <= 0xff

        return [ type_, len(data) ] + data

    @staticmethod
    def make_snmp_integer(v: int):
        bytes_ = v.to_bytes(8, byteorder='big', signed=True)

        array = [x for x in bytes_]

        while len(array) > 1 and array[0] == 0:
            del array[0]

        return snmp_client.make_snmp_BER(0x02, array)

    @staticmethod
    def make_snmp_octetstring(s: str):
        array = [ord(x) for x in s]

        return snmp_client.make_snmp_BER(0x04, array)

    @staticmethod
    def make_snmp_null():
        return snmp_client.make_snmp_BER(0x05, [])

    @staticmethod
    def make_snmp_oid(name):
        out = []

        if name[0:4] == '1.3.':
            out.append(43)

            name = name[4:]

        values = [int(v) for v in name.split('.')]

        for v in values:
            work = v

            b7 = []

            if work == 0:
                b7.append(0)

            use_bit = 128 if work > 127 else 0

            while work > 0:
                b7.insert(0, (work & 127))

                work >>= 7

            for i in range(0, len(b7) - 1):
                b7[i] |= 128

            out += b7

        return [0x06, len(out)] + out

    @staticmethod
    def make_snmp_sequence(*inputs):
        combined = []

        for input_ in inputs:
            combined += input_

        return snmp_client.make_snmp_BER(0x30, combined)

    @staticmethod
    def make_snmp_message(version, community, request):
        return snmp_client.make_snmp_sequence(snmp_client.make_snmp_integer(version), snmp_client.make_snmp_octetstring(community), request)

    @staticmethod
    def make_snmp_get_request(version, community, oids):
        varbind_list = list()

        for o in oids:
            bin_oid = snmp_client.make_snmp_oid(o)

            varbind_list += snmp_client.make_snmp_sequence(bin_oid, snmp_client.make_snmp_null())

        return snmp_client.make_snmp_message(version, community, snmp_client.make_snmp_BER(0xa0, snmp_client.make_snmp_integer(1) + snmp_client.make_snmp_integer(0) + snmp_client.make_snmp_integer(0) + snmp_client.make_snmp_sequence(varbind_list)))

    @staticmethod
    def unittest(self):
        assert snmp_client.make_snmp_BER(0x030, [ 1, 2, 3, 4 ]) == [48, 4, 1, 2, 3, 4]
        assert snmp_client.make_snmp_integer(-123) == [2, 8, 255, 255, 255, 255, 255, 255, 255, 133]
        assert snmp_client.make_snmp_integer(131071) == [2, 3, 1, 255, 255]
        assert snmp_client.make_snmp_octetstring('test 1234') == [4, 9, 116, 101, 115, 116, 32, 49, 50, 51, 52]
        assert snmp_client.make_snmp_null() == [5, 0]
        assert snmp_client.make_snmp_message(1, 'public', snmp_client.make_snmp_null()) == [48, 13, 2, 1, 1, 4, 6, 112, 117, 98, 108, 105, 99, 5, 0]
        assert snmp_client.make_snmp_oid('1.3.6.1.4.1.2680.1.2.7.3.2.0') == [6, 13, 43, 6, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 0]
        assert snmp_client.make_snmp_get_request(0, 'private', ['1.3.6.1.4.1.2680.1.2.7.3.2.0']) == [48, 44, 2, 1, 0, 4, 7, 112, 114, 105, 118, 97, 116, 101, 160, 30, 2, 1, 1, 2, 1, 0, 2, 1, 0, 48, 19, 48, 17, 6, 13, 43, 6, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 0, 5, 0]

    @staticmethod
    def get_snmp_BER(data, offset):
        if data[offset + 1] + 2 > len(data):
            print(f'Field length wrong: {data[offset + 1] + 2} does not fit in {len(data)} at offset {offset}')

        return ((data[offset + 0], data[offset + 2:offset + 2 + data[offset + 1]]), data[offset + 1] + 2)

    @staticmethod
    def get_snmp_integer(data, offset):
        if data[offset] != 0x02:
            print(f'Expected integer at {offset}, got type 0x{data[offset]:02x}')

        if data[offset + 1] + 2 > len(data):
            print(f'Field length wrong: {data[offset + 1] + 2} does not fit in {len(data)} at offset {offset}')

        v = 0

        for i in range(0, data[offset + 1]):
            cv = data[offset + 2 + i]

            v <<= 8
            v |= cv

        return (v, data[offset + 1] + 2)

    @staticmethod
    def get_snmp_octetstring(data, offset):
        if data[offset] != 0x04:
            print(f'Expected octetstring at {offset}, got type 0x{data[offset]:02x}')

        if data[offset + 1] + 2 > len(data):
            print(f'Field length wrong: {data[offset + 1] + 2} does not fit in {len(data)} at offset {offset}')

        return (data[offset + 2:offset + 2 + data[offset + 1]], data[offset + 1] + 2)

    @staticmethod
    def get_sequence(data, offset):
        if data[offset] != 0x30:
            print(f'Expected sequence at {offset}, got type 0x{data[offset]:02x}')

        if data[offset + 1] + 2 > len(data):
            print(f'Field length wrong: {data[offset + 1] + 2} does not fit in {len(data)} at offset {offset}')

        return (data[offset + 2:offset + 2 + data[offset + 1]], data[offset + 1] + 2)

    @staticmethod
    def get_pdu(data, offset):
        if data[offset] != 0xa0 and data[offset] != 0xa2:
            print(f'Expected pdu(0xa0/0xa2) at {offset}, got type 0x{data[offset]:02x}')

        pdu_payload_len = data[offset + 1];

        if pdu_payload_len + 2 > len(data):
            print(f'Field length wrong: {data[offset + 1] + 2} does not fit in {len(data)} at offset {offset}')

        offset += 2

        request_id = snmp_client.get_snmp_integer(data, offset)
        offset += request_id[1]

        error = snmp_client.get_snmp_integer(data, offset)
        offset += error[1]

        error_index = snmp_client.get_snmp_integer(data, offset)
        offset += error_index[1]

        varbind_list = snmp_client.get_sequence(data, offset)
        offset += varbind_list[1]

        oids = []

        # retrieve oid/value pairs from varbind_list
        work = varbind_list[0]
        work_len = varbind_list[1] - 2
        work_offset = 0

        while work_len > 0:
            varbind = snmp_client.get_sequence(work, work_offset)

            work_offset += varbind[1]
            work_len -= varbind[1]

            oid = snmp_client.get_snmp_BER(varbind[0], 0)

            value = snmp_client.get_snmp_BER(varbind[0], oid[1])

            oids.append((oid[0], value[0]))

        if work_len < 0:
            print(f'Varbind inner size incorrect: {work_len} short')

        return ((request_id[0], error[0], error_index[0], oids), pdu_payload_len + 2)
