

import socket
import struct
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

TLS_HANDSHAKE = 0x16
TLS_ALERT = 0x15
TLS_APPLICATION_DATA = 0x17
TLS_VERSION = (3, 3)

ALERT_DECRYPT_ERROR = 51

#hardcoded sensitive premaster secret for demonstration (in practice, this would be randomly generated)
SENSITIVE_PREMASTER_SECRET = b"CRITICAL_SECRET_48_BYTES_LONG_12345678901234567890"

class SimpleTLSServer:
    def __init__(self, host='localhost', port=4433):
        self.host = host
        self.port = port
        self.private_key = None
        self.public_key = None
        self.generate_rsa_keypair()

    def generate_rsa_keypair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print("[Server] Generated RSA-2048 keypair")

    def pkcs1_decrypt(self, ciphertext):
        try:
            plaintext = pow(
                int.from_bytes(ciphertext, 'big'),
                self.private_key.private_numbers().d,
                self.private_key.private_numbers().public_numbers.n
            )
            plaintext_bytes = plaintext.to_bytes(256, 'big')

            if plaintext_bytes[0] != 0x00:
                time.sleep(0.005)  
                return False, None
            if plaintext_bytes[1] != 0x02:
                time.sleep(0.010)  
                return False, None

            #check for non-zero padding bytes and null separator
            for i in range(2, len(plaintext_bytes)):
                if plaintext_bytes[i] == 0x00:
                    if i < 10:
                        time.sleep(0.015) 
                        return False, None
                    #successful decryption: Expose sensitive premaster secret
                    print("[Server] WARNING: Bleichenbacher attack succeeded, exposing sensitive data!")
                    return True, SENSITIVE_PREMASTER_SECRET
            time.sleep(0.020)
            return False, None

        except Exception as e:
            print(f"[Server] Decryption error: {e}")
            time.sleep(0.025) 
            return False, None

    def handle_client_key_exchange(self, encrypted_premaster):
        print(f"[Server] Received encrypted premaster secret ({len(encrypted_premaster)} bytes)")
        is_valid, premaster = self.pkcs1_decrypt(encrypted_premaster)
        if is_valid:
            print("[Server] Valid PKCS#1 padding detected")
            #demonstrate danger by exposing sensitive data
            print(f"[Server] Exposed sensitive premaster secret: {premaster.decode('utf-8')}")
            return True
        else:
            print("[Server] Invalid PKCS#1 padding - sending alert")
            return False

    def send_tls_alert(self, conn, alert_code):
        alert_msg = struct.pack('!BB', 2, alert_code)
        tls_header = struct.pack('!BBH', TLS_ALERT, TLS_VERSION[0], TLS_VERSION[1])
        tls_header += struct.pack('!H', len(alert_msg))
        conn.send(tls_header + alert_msg)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(1)
            print(f"[Server] Listening on {self.host}:{self.port}")

            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open('server_public_key.pem', 'wb') as f:
                f.write(pem)
            print("[Server] Public key exported to server_public_key.pem")

            while True:
                conn, addr = sock.accept()
                print(f"[Server] Connection from {addr}")
                try:
                    header = conn.recv(5)
                    if len(header) < 5:
                        continue
                    msg_type, major, minor, length = struct.unpack('!BBBH', header)
                    data = conn.recv(length)
                    if msg_type == TLS_HANDSHAKE:
                        if self.handle_client_key_exchange(data):
                            response = b"OK"
                            tls_header = struct.pack('!BBBH', TLS_APPLICATION_DATA,
                                                    major, minor, len(response))
                            conn.send(tls_header + response)
                        else:
                            self.send_tls_alert(conn, ALERT_DECRYPT_ERROR)
                except Exception as e:
                    print(f"[Server] Error: {e}")
                finally:
                    conn.close()

if __name__ == "__main__":
    print("=== Bleichenbacher RSA Padding Oracle Server ===")
    server = SimpleTLSServer()
    try:
        server.run()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down...")