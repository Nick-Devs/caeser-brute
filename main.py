import string
import gzip
import io
import hashlib

def caesar_decrypt(ciphertext, keyletter):
    keyrotate = ord(keyletter.upper()) - ord('A')
    plaintext = ''
    skipped = 0

    # Decode bytes if needed
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

out = caesar_decrypt(ciphertext, keyletter)
print(out)