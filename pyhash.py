from cryptography.hazmat.primitives import hashes, hmac
import binascii
import sys

st = "The quick brown fox jumps over the lazy dog"
hex = False
showHex = "No"
k = "00"


def show_hash(name, type, data, key):
    digest = hmac.HMAC(key, type)
    digest.update(data)
    res = digest.finalize()
    hex = binascii.b2a_hex(res).decode()
    b64 = binascii.b2a_base64(res).decode()
    print(f"HMAC={name}: {hex} {b64}")


if len(sys.argv) > 1:
    st = str(sys.argv[1])

if len(sys.argv) > 2:
    showHex = str(sys.argv[2])

if len(sys.argv) > 3:
    k = str(sys.argv[3])

if showHex == "yes":
    hex = True

try:
    if hex == True:
        data = binascii.a2b_hex(st)
    else:
        data = st.encode()

    if hex == True:
        key = binascii.a2b_hex(k)
    else:
        key = k.encode()

    print("Data: ", st)
    print("Hex: ", binascii.b2a_hex(data).decode())
    print("Key: ", k)
    print("Hex: ", binascii.b2a_hex(key).decode())
    print()

    show_hash("Blake2p (64 bytes)", hashes.BLAKE2b(64), data, key)
    show_hash("Blake2s (32 bytes)", hashes.BLAKE2s(32), data, key)
    show_hash("MD5", hashes.MD5(), data, key)
    show_hash("SHA1", hashes.SHA1(), data, key)
    show_hash("SHA224", hashes.SHA224(), data, key)
    show_hash("SHA256", hashes.SHA256(), data, key)
    show_hash("SHA384", hashes.SHA384(), data, key)
    show_hash("SHA3_224", hashes.SHA3_224(), data, key)
    show_hash("SHA3_256", hashes.SHA3_256(), data, key)
    show_hash("SHA3_384", hashes.SHA3_384(), data, key)
    show_hash("SHA3_512", hashes.SHA3_512(), data, key)
    show_hash("SHA512", hashes.SHA512(), data, key)
    show_hash("SHA512_224", hashes.SHA512_224(), data, key)
    show_hash("SHA512_256", hashes.SHA512_256(), data, key)

except Exception as e:
    print(e)
