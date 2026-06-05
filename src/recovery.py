import hashlib
import binascii
from pathlib import Path
from exract import FritzBoxHash


def pbkdf2(data, salt, iterations, dklen=32):
    return hashlib.pbkdf2_hmac(
        'sha256',
        data,
        salt,
        iterations,
        dklen
    )

def hex_to_bytes(h):
    return binascii.unhexlify(h)

def simulate(password, salt1_hex, iter1, salt2_hex, iter2):
    password = password.encode()

    salt1 = hex_to_bytes(salt1_hex)
    salt2 = hex_to_bytes(salt2_hex)

    # Runde 1
    result1 = pbkdf2(password, salt1, iter1)

    # Runde 2
    result2 = pbkdf2(result1, salt2, iter2)

    return result2

def hash_conv(hash_list: Path):
    h_lst : list[FritzBoxHash] = []

    with open(hash_list, 'r') as f:
        for line in f:
            parts = line.split()
            h_lst.append(FritzBoxHash(parts[0], parts[1]))




#
def cracker(hash_lst: Path, wordlist: Path):
    pot_buffer = []
    with open(hash_lst, 'r') as f:
        for line in f:
            parts = line.split(':')
            expect = parts[4].rstrip()

            print(f"[*] Start cracking: {parts[4]}")
            with open(wordlist, 'r') as w:
                for word in w:
                    res = simulate(word.rstrip("\n"), parts[1], int(parts[0]), parts[3], int(parts[2]))
                    if res.hex() == expect:
                        pot_hash = f"{expect}:{word}"
                        print(f"[+] BINGO! {pot_hash}")
                        pot_buffer.append(pot_hash)
                        break

    pot_file : Path = Path("~/.cracker.potfile").expanduser()
    with open(pot_file, 'a') as c:
        for pot in pot_buffer:
            c.write(pot + "\n")

