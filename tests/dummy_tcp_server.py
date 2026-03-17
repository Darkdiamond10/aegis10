import socket
import threading

EIGHT_MB = 8 * 1024 * 1024

def handle_client(conn):
    try:
        # Read the HTTP GET request
        conn.recv(1024)

        # We need to send exactly 8MB of the repeating string "AEGIS"
        # Since AEGIS is 5 bytes, we generate enough string to cover 8MB
        pattern = b"AEGIS"
        repeats = EIGHT_MB // len(pattern)
        remainder = EIGHT_MB % len(pattern)

        payload = (pattern * repeats) + pattern[:remainder]

        # Build the HTTP response header
        header = f"HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n\r\n".encode()

        # Send the whole chunk at once over the raw TCP socket
        conn.sendall(header + payload)

    except Exception as e:
        print(f"[!] Server exception: {e}")
    finally:
        conn.close()

def run_server():
    bindsocket = socket.socket()
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind(('127.0.0.1', 4444))
    bindsocket.listen(5)

    print("[*] Python Dummy TCP Server Listening on 127.0.0.1:4444")

    while True:
        conn, fromaddr = bindsocket.accept()
        threading.Thread(target=handle_client, args=(conn,)).start()

if __name__ == '__main__':
    run_server()