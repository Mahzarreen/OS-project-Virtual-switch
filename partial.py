import socket, struct, time
s = socket.create_connection(("127.0.0.1", 9000))
frame = struct.pack("!H6s6sHB", 5, bytes.fromhex("020000000099"), b"\xff" * 6, 1, 1) + b"split"
for b in frame:
    s.send(bytes([b]))
    time.sleep(0.05)
s.send(frame[:9])
s.close()
