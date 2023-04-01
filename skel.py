import base64 as b64
from time import sleep
from pwn import *


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

GUEST_NAME = b"Anonymous"
GOOD_NAME = b"Ephvuln"
 
LOCAL = False  # Local means that you run binary directly
 
if LOCAL:
    # Complete this if you want to test locally
    r = process("/home/alex/facultate/ic/tema1/server.py")
else:
    r = remote("141.85.224.117", 1337)  # Complete this if changed
 
def read_options():
    """Reads server options menu."""
    r.readuntil(b"Input:")
 
def get_token():
    """Gets anonymous token as bytearray."""
    read_options()
    r.sendline(b"1")
    sleep(0.01)
    token = r.readline()[:-1]
    return b64.b64decode(token)
 
def login(tag):
    """Expects bytearray. Sends base64 tag."""
    r.readline()
    read_options()
    r.sendline(b"2")
    sleep(0.01) # Uncoment this if server rate-limits you too hard
    r.sendline(b64.b64encode(tag))
    r.readuntil(b"Token:")
    response = r.readline().strip()
    return response
 
def main():
    # pentru inceput iau token-ul de la server
    guest_token = get_token()
    
    # fac cele doua operatii de XOR pentru a afla initial cheia
    key = byte_xor(guest_token, GUEST_NAME)
    # apoi folosindu-ma de cheie aflu cipher-ul pentru Ephvuln
    good_cipher = byte_xor(GOOD_NAME, key)

    # SERVER_PUBLIC_BANNER (SPB)
    # separ spb-ul de restul token-ului primit
    # pentru a il putea alipi la noul token.
    # primii 9 bytes sunt de la username iar ultimul de la integrity
    spb = guest_token[9:len(guest_token) - 1]

    # incepem atacul prin bruteforce in care iteram
    # print toate valorile posibile ale lui integrity
    for i in range(256):
        # construiesc token-ul de atac prin concatenarea tuturor componentelor
        attack_token = good_cipher + spb + i.to_bytes(1, "big")
        
        # trimit token-ul meu catre server
        login(attack_token)

        # primesc raspuns de la server si il decodific
        response = login(attack_token).decode('utf-8')
        
        # daca am gasit flag-ul
        if "CTF" in response:
            # il afisam
            print("[*] Found flag:",response)
            # inchidem conexiunea
            r.close()
            # si terminam programul deoarece si-a atins scopul
            exit()

if __name__ == "__main__":
    main()