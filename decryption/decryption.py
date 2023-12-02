import json

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyInterface
from pyhpke.kem import KEM
from random import randrange
import sys

if __name__ == "__main__":
    n_test = 4
    f = open('test_data.json')
    data = json.load(f)
    i = randrange(n_test) + 1 
    test = "test" + str(i)
    data = data[test]
    mode = data["mode"]
    print("Mode: " + str(mode))
    
    if "kem_id" in data and "kdf_id" in data and "aead_id" in data:
        kemID = data["kem_id"]
        kdfID = data["kdf_id"]
        aeadID = data["aead_id"]
    else:
        sys.exit("Error, missing id parameters")

    # create ciphersuite
    suite_r = CipherSuite.new(
        KEMId(kemID),
        KDFId(kdfID),
        AEADId(aeadID)
    )

    # le stringhe nei test vectors contengono due caratteri esadecimali per ogni byte
    # quindi stringhe di 64 caratteri ad es., sono in realtà 32 bytes una volta decodificate
    my_sk = suite_r.kem.deserialize_private_key(bytes.fromhex(data["skRm"]))
    my_pk = suite_r.kem.deserialize_public_key(bytes.fromhex(data["pkRm"]))
    sender_pk = None
    enc = bytes.fromhex(data["enc"])
    
    if "pkSm" in data:
       sender_pk = suite_r.kem.deserialize_public_key(bytes.fromhex(data["pkSm"]))
    
    psk = bytes.fromhex(data["psk"]) if "psk" in data else b""
    psk_id = bytes.fromhex(data["psk_id"]) if "psk_id" in data else b""
    info = bytes.fromhex(data["info"]) if "info" in data else b""
    aad = bytes.fromhex(data["aad"]) if "aad" in data else b""    
    ct = bytes.fromhex(data["ct"]) if "ct" in data else ""
    
    receiving = suite_r.create_recipient_context(enc, my_sk, info, sender_pk, psk, psk_id)
    print("In decryption...")
    plaintext = receiving.open(ct, aad).decode()
    
    if "pt" in data:
        original_plain_text = bytes.fromhex(data["pt"]).decode()
        print("Plaintext: "+plaintext)
        print("Original plaintext: "+original_plain_text)
        if plaintext == original_plain_text:
            print("=> OK DECRYPTION")
        else:
            print("=> Error in decryption")
    else:
        print("Plaintext: "+plaintext)
