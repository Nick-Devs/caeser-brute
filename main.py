import string
import gzip
import io
import hashlib

def caesar_decrypt(ciphertext, keyletter):
    keyrotate = ord(keyletter.upper()) - ord('A')
    plaintext = ''
    skipped = 0

    if isinstance(ciphertext, bytes):
        ciphertext = ciphertext.decode('ascii', errors='ignore')

    for c in ciphertext:
        if c in string.ascii_uppercase:
            val = (ord(c) - ord('A') - keyrotate) % 26
            plaintext += chr(ord('A') + val)
        else:
            skipped += 1

    return plaintext

ciphertext = 'VGLFFNPEVSVPRFPBNFGNYQEHOEBOVAFCNEDHRGVATCHZCFZRQVPNGRQQBGFBAEBKVRGVAFZVGUFTNMVYYVBAFWBVAFYVORENYVMNGVBAPNVAFORGURHAPNAAVREYVDHVQVMVATFLPNZBEROHYYQBMREZBEGVPVNAANVYOEHFUFCEBPEHFGRNAANEPVFFHFFCNERAGURFVMRQOVOYVPNYFBYVIRFGNZZVFZNVAGNVAPBAGEBYZNVAFGERNZRQPBAPNIRPYVZNGVPORNHGVSVREFFYVTUGYLFVATRPBATENGHYNGRFPNQVYYNPFCUBGBANAGVPUEVFGFCBEPUFGNPPNGVCEBSNANGVBAQENVACVCRFCEBGBMBNTNYYVINAGVATYBPNYYLEUVABFOYH'
target_hash = '96fd5be640548c4af9ee85ad8bcec52a2ec781f23fb508dbe8660c07361c30b7222dfac2556f3a3d70b35222bc999134b762f33dbebb4df954cf725287af2f0c'

for keyletter in string.ascii_uppercase:
    out = caesar_decrypt(ciphertext, keyletter)

    # Compute SHA512 hash of candidate plaintext
    out_hash = hashlib.sha512(out.encode('utf-8')).hexdigest()

    if out_hash == target_hash:
        print(f"[+] Match found! Key = {keyletter}")
        print(f"Decrypted plaintext:\n{out}")
        break
else:
    print("[-] No match found among A–Z.")

#out = caesar_decrypt(ciphertext, keyletter)
#print(out)

def rrot(n, d):
    d &= 7
    return ((n >> d) | (n << (8 - d))) & 0xff

def decrypt_julia(ciphertext, keyshift, keyxorasstring, output_txtfile, decompress_gzip=True):
    if not isinstance(keyshift, int) or not (1 <= keyshift <= 7):
        raise ValueError("keyshift must be an integer between 1 and 7")
    if not isinstance(keyxorasstring, str) or len(keyxorasstring) != 12:
        raise ValueError("keyxorasstring must be a 12-character string")

    keyxor = [ord(c) for c in keyxorasstring]

    plaintext_bytes = bytearray()
    for i, cb in enumerate(ciphertext):
        val = cb ^ keyxor[i % len(keyxor)]
        p = rrot(val, keyshift)
        plaintext_bytes.append(p)
    if decompress_gzip:
        try:
            plaintext_bytes = gzip.decompress(bytes(plaintext_bytes))
        except Exception as e:
            print("Warning: gzip decompression failed:", e)

    with open(output_txtfile, "wb") as f:
        f.write(plaintext_bytes)

    sha512 = hashlib.sha512()
    with open(output_txtfile, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha512.update(chunk)
    sha512_hash = sha512.hexdigest()

    print(f"Decryption complete! Plaintext written to: {output_txtfile}")
    print(f"SHA-512 of the file: {sha512_hash}")

    return sha512_hash


with open("juliaplaintext.txt.gz.enc", "rb") as f:
    ciphertext = f.read()

sha = decrypt_julia(ciphertext, 2, "HWAVRSFgeQii", "decrypted_output.txt")