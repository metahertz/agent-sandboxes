#!/usr/bin/python3 -I
"""Inside a microVM workspace: the guest's only way out.

The guest has no network interface. This listens on TCP 3128 (loopback, and
Docker's bridges, so containers in the guest can use it too) and relays each
connection over vsock to the host (CID 2), where the proxy service hands it to
this workspace's nono proxy: the allowlist, API tokens and audit log all live
on the host. HTTP(S)_PROXY in the guest point here.

The other way, for the browser container (when the workspace has one): vsock
port 8080, which only the host can reach, to the container on 127.0.0.1:8080,
for the web UI's Browser, VS Code and Terminal tabs.
"""
import asyncio
import socket

PORT = 3128
BROWSER_PORT = 8080


async def pump(r: asyncio.StreamReader, w: asyncio.StreamWriter):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
        if w.can_write_eof():
            w.write_eof()
    except OSError:
        pass


async def handle(r: asyncio.StreamReader, w: asyncio.StreamWriter):
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        await asyncio.get_running_loop().sock_connect(s, (socket.VMADDR_CID_HOST, PORT))
        ur, uw = await asyncio.open_connection(sock=s)
    except OSError:
        s.close()
        w.close()
        return
    try:
        await asyncio.gather(pump(r, uw), pump(ur, w))
    finally:
        w.close()
        uw.close()


async def handle_host(r: asyncio.StreamReader, w: asyncio.StreamWriter):
    try:
        ur, uw = await asyncio.open_connection("127.0.0.1", BROWSER_PORT)
    except OSError:
        w.close()
        return
    try:
        await asyncio.gather(pump(r, uw), pump(ur, w))
    finally:
        w.close()
        uw.close()


async def main():
    out = await asyncio.start_server(handle, "0.0.0.0", PORT)
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.bind((socket.VMADDR_CID_ANY, BROWSER_PORT))
    s.listen(64)
    back = await asyncio.start_server(handle_host, sock=s)
    async with out, back:
        await asyncio.gather(out.serve_forever(), back.serve_forever())


asyncio.run(main())
