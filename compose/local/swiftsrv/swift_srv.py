import os
import socketserver

from umbrella.swift import demangle
from caterpillar.shortcuts import unpack, pack

import swiftsrv_format as fmt


class PacketHandler(socketserver.BaseRequestHandler):

    def handle(self) -> None:
        self.data = self.request.recv(2048).strip()
        # decode packet
        try:
            p = unpack(fmt.packet_t, self.data)
        except Exception:
            # ignore
            return

        op = p.operation
        content = b""

        if not p.is_valid():
            op = fmt.Operation.FAIL
        else:
            if p.operation == fmt.Operation.DEMANGLE:
                content = demangle(p.payload).encode()

        response = fmt.packet_t(op, content, fmt.get_checksum(content))
        self.request.sendall(pack(response))


if __name__ == "__main__":
    SRV_HOST_ADDRESS = os.environ.get("SWIFTSRV_HOST", "0.0.0.0")
    SRV_PORT = os.environ.get("SWIFTSRV_PORT", 1298)

    with socketserver.ThreadingTCPServer(
        (SRV_HOST_ADDRESS, int(SRV_PORT)), PacketHandler
    ) as srv:
        srv.serve_forever()
