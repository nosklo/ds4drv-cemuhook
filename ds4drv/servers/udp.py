from __future__ import division

import collections
from builtins import bytes
from typing import Any, Dict, Tuple

import attr

import threading

import socket
import struct
import binascii
from time import time
import enum

import re

PROTOCOL_VERSION = 1001


class MessageType(enum.Enum):
    version = b'\x00\x00\x10\x00'
    ports = b'\x01\x00\x10\x00'
    data = b'\x02\x00\x10\x00'


SERVER_MAGIC = b'DSUS'
CLIENT_MAGIC = b'DSUC'

_HEADER = SERVER_MAGIC + struct.pack('<H', PROTOCOL_VERSION)


@attr.s(auto_attribs=True)
class Message:
    message_type: MessageType
    data: bytes

    def serialize(self) -> bytes:
        header = bytearray(_HEADER)

        # add data length (message type is part of it):
        header += struct.pack('<H', len(self.data) + 4)

        # server ID:
        payload = bytearray(b'\xff' * 4)

        # message type:
        payload += self.message_type.value

        # add the data
        payload += self.data

        # calculate the crc32
        crc = struct.pack('<I', binascii.crc32(header + b'\x00' * 4 + payload) & 0xffffffff)

        # add it
        payload = header + crc + payload

        return payload


TAddress = Tuple[str, int]


@attr.s(auto_attribs=True)
class ControllerData:
    clients: Dict[TAddress, float] = attr.ib(init=False, factory=dict)
    mac: bytes = attr.ib(init=False, default=bytes(6))


@attr.s(auto_attribs=True)
class UDPServer:
    host: str = ''
    port: int = 26760
    controllers: Dict[int, ControllerData] = attr.ib(init=False,
                                                     factory=lambda: collections.defaultdict(ControllerData))
    counter: int = attr.ib(init=False, default=0)
    _per_client_send_lock: Dict[TAddress, threading.Lock] = attr.ib(init=False,
                                                                    factory=lambda: collections.defaultdict(threading.Lock))

    def __attrs_post_init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))

    def _res_ports(self, pad_id: int) -> Message:
        return Message(MessageType.ports, bytes([
            pad_id,  # pad id
            0x02,  # state (connected)
            0x02,  # model (full gyro)
            0x01,  # connection type (usb)
            *self.controllers[pad_id].mac,  # 6 bytes mac address
            0xef,  # battery (charged)
            0x00,  # fixed zero on ports response.
        ]))

    def _req_ports(self, message: bytes, address: TAddress):
        requests_count = struct.unpack("<i", message[20:24])[0]
        for i in range(requests_count):
            index = message[24 + i]
            if index in self.controllers:
                with self._per_client_send_lock[address]:
                    self.sock.sendto(self._res_ports(index).serialize(), address)

    def _req_data(self, message: bytes, address: TAddress):
        flags = message[20]
        pad_id = message[21]

        if flags == 0:
            # register for all controllers
            for pad_id, controller_data in self.controllers.items():
                controller_data.clients[address] = time()
        elif flags == 1:
            controller_data = self.controllers.get(pad_id)
            if controller_data is None:
                print(f'[udp] Client {address} requested {pad_id=}, ignoring')
            else:
                if address not in controller_data.clients:
                    print('[udp] Client {0[0]}:{0[1]} connected to {1}'.format(address, pad_id))
                controller_data.clients[address] = time()
        # elif flags == 2: # TODO: implement mac based connect
        else:
            print(f'[udp] Client {address} requested {flags=} {pad_id=}, ignoring')

    def _res_data(self, pad_id: int, message: Message):
        now = time()
        controller_data = self.controllers[pad_id]
        for address in list(controller_data.clients):
            if now - controller_data.clients.get(address, 5) < 2:
                with self._per_client_send_lock[address]:
                    self.sock.sendto(message.serialize(), address)
            else:
                print('[udp] Client {0[0]}:{0[1]} disconnected from {1}'.format(address, pad_id))
                del controller_data.clients[address]

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
        self.device_for_pad(0x00, device)

    def device_for_pad(self, pad_id: int, device):
        mac = device.device_addr
        mac_int = self.mac_to_int(mac)

        self.controllers[pad_id].mac = mac_int.to_bytes(6, "big")

    def report(self, report):
        return self.report_for_pad(0x00, report)

    def report_for_pad(self, pad_id: int, report):
        data = [
            pad_id,  # pad id
            0x02,  # state (connected)
            0x02,  # model (generic)
            0x01,  # connection type (usb)
            *self.controllers[pad_id].mac,  # 6 bytes mac address
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
        # if not self.remap:
        buttons2 |= report.button_triangle << 4
        buttons2 |= report.button_circle << 5
        buttons2 |= report.button_cross << 6
        buttons2 |= report.button_square << 7
        # else:
        #     buttons2 |= report.button_triangle << 7
        #     buttons2 |= report.button_circle << 6
        #     buttons2 |= report.button_cross << 5
        #     buttons2 |= report.button_square << 4

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

        self._res_data(pad_id, Message(MessageType.data, bytes(data)))

    def _worker(self):
        while True:
            self._handle_request(self.sock.recvfrom(1024))

    def start(self):
        self.thread = threading.Thread(target=self._worker)
        self.thread.daemon = True
        self.thread.start()
