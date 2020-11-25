from __future__ import division
from builtins import bytes

import attr

from threading import Thread
import sys
import socket
import struct
from binascii import crc32
from time import time
import enum

import re


class MessageType(enum.Enum):
    version = b'\x00\x00\x10\x00'
    ports = b'\x01\x00\x10\x00'
    data = b'\x02\x00\x10\x00'


HEADER = bytes(
    [
        0x44, 0x53, 0x55, 0x53,  # DSUS,
        0xE9, 0x03,  # protocol version (1001),
    ])


@attr.s(auto_attribs=True)
class Message:
    message_type: MessageType
    data: bytes

    def serialize(self) -> bytes:
        header = bytearray(HEADER)

        # add data length:
        header += struct.pack('<H', len(self.data) + 4)

        # server ID:
        payload = bytearray(b'\xff' * 4)

        # message type:
        payload += self.message_type.value

        # add the data
        payload += self.data

        # calculate the crc32
        crc = struct.pack('<I', crc32(header + b'\x00' * 4 + payload) & 0xffffffff)

        # add it
        payload = header + crc + payload

        return payload


class UDPServer:
    mac_int_bytes = bytes(6)

    def __init__(self, host='', port=26760):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.counter = 0
        self.clients = dict()
        self.remap = False

    def _res_ports(self, index):
        return Message(MessageType.ports, bytes([
            index,  # pad id
            0x02,  # state (connected)
            0x03,  # model (generic)
            0x01,  # connection type (usb)
            self.mac_int_bytes[0], self.mac_int_bytes[1], self.mac_int_bytes[2], self.mac_int_bytes[3],
            self.mac_int_bytes[4], self.mac_int_bytes[5],
            0xef,  # battery (charged)
            0x00,  # ?
        ]))

    def _req_ports(self, message, address):
        requests_count = struct.unpack("<i", message[20:24])[0]
        for i in range(requests_count):
            index = message[24 + i]

            if index != 0:  # we have only one controller
                continue

            self.sock.sendto(self._res_ports(index).serialize(), address)

    def _req_data(self, message, address):
        flags = message[24]
        reg_id = message[25]
        # reg_mac = message[26:32]

        if flags == 0 and reg_id == 0:  # TODO: Check MAC
            if address not in self.clients:
                print('[udp] Client connected: {0[0]}:{0[1]}'.format(address))

            self.clients[address] = time()

    def _res_data(self, message):
        now = time()
        for address, timestamp in self.clients.copy().items():
            if now - timestamp < 2:
                self.sock.sendto(message, address)
            else:
                print('[udp] Client disconnected: {0[0]}:{0[1]}'.format(address))
                del self.clients[address]

    def _handle_request(self, request):
        message, address = request

        # client_id = message[12:16]
        msg_type = MessageType(message[16:20])

        if msg_type == MessageType.version:
            return
        elif msg_type == MessageType.ports:
            self._req_ports(message, address)
        elif msg_type == MessageType.data:
            self._req_data(message, address)
        else:
            print(f'[udp] Unknown message type from {message[12:16]}: {message[16:20]}')

    @staticmethod
    def mac_to_int(mac):
        res = re.match('^((?:(?:[0-9a-f]{2}):){5}[0-9a-f]{2})$', mac.lower())
        if res is None:
            raise ValueError('invalid mac address')
        return int(res.group(0).replace(':', ''), 16)

    def device(self, device):
        mac = device.device_addr
        mac_int = self.mac_to_int(mac)
        self.mac_int_bytes = mac_int.to_bytes(6, "big")

    def report(self, report):
        if len(self.clients) == 0:
            return None

        data = [
            0x00,  # pad id
            0x02,  # state (connected)
            0x02,  # model (generic)
            0x01,  # connection type (usb)
            *self.mac_int_bytes,  # 6 bytes mac address
            0xef,  # battery (charged)
            0x01  # is active (true)
        ]

        data.extend(bytes(struct.pack('<I', self.counter)))
        self.counter += 1

        buttons1 = 0x00
        buttons1 |= report.button_share
        buttons1 |= report.button_l3 << 1
        buttons1 |= report.button_r3 << 2
        buttons1 |= report.button_options << 3
        buttons1 |= report.dpad_up << 4
        buttons1 |= report.dpad_right << 5
        buttons1 |= report.dpad_down << 6
        buttons1 |= report.dpad_left << 7

        buttons2 = 0x00
        buttons2 |= report.button_l2
        buttons2 |= report.button_r2 << 1
        buttons2 |= report.button_l1 << 2
        buttons2 |= report.button_r1 << 3
        if not self.remap:
            buttons2 |= report.button_triangle << 4
            buttons2 |= report.button_circle << 5
            buttons2 |= report.button_cross << 6
            buttons2 |= report.button_square << 7
        else:
            buttons2 |= report.button_triangle << 7
            buttons2 |= report.button_circle << 6
            buttons2 |= report.button_cross << 5
            buttons2 |= report.button_square << 4

        data.extend([
            buttons1, buttons2,
            report.button_ps * 0xFF,
            report.button_trackpad * 0xFF,

            report.left_analog_x,
            255 - report.left_analog_y,
            report.right_analog_x,
            255 - report.right_analog_y,

            report.dpad_left * 0xFF,
            report.dpad_down * 0xFF,
            report.dpad_right * 0xFF,
            report.dpad_up * 0xFF,

            report.button_square * 0xFF,
            report.button_cross * 0xFF,
            report.button_circle * 0xFF,
            report.button_triangle * 0xFF,

            report.button_r1 * 0xFF,
            report.button_l1 * 0xFF,

            report.r2_analog,
            report.l2_analog,

            report.trackpad_touch0_active * 0xFF,
            report.trackpad_touch0_id,

            report.trackpad_touch0_x >> 8,
            report.trackpad_touch0_x & 255,
            report.trackpad_touch0_y >> 8,
            report.trackpad_touch0_y & 255,

            report.trackpad_touch1_active * 0xFF,
            report.trackpad_touch1_id,

            report.trackpad_touch1_x >> 8,
            report.trackpad_touch1_x & 255,
            report.trackpad_touch1_y >> 8,
            report.trackpad_touch1_y & 255,
        ])

        data.extend(bytes(struct.pack('<Q', int(time() * 10 ** 6))))

        sensors = [
            report.orientation_roll / 8192,
            - report.orientation_yaw / 8192,
            - report.orientation_pitch / 8192,
            report.motion_y / 16,
            - report.motion_x / 16,
            - report.motion_z / 16,
        ]

        for sensor in sensors:
            data.extend(bytes(struct.pack('<f', float(sensor))))

        self._res_data(Message(MessageType.data, bytes(data)).serialize())

    def _worker(self):
        while True:
            self._handle_request(self.sock.recvfrom(1024))

    def start(self):
        self.thread = Thread(target=self._worker)
        self.thread.daemon = True
        self.thread.start()
