import json

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyInterface
from pyhpke.kem import KEM

if __name__ == "__main__":
    # read the json file
    f = open('message_info.json')
    data = json.load(f)

    # create ciphersuite
    suite_r = CipherSuite.new(
        KEMId(int(data["kem_id"])),
        KDFId(int(data["kdf_id"])),
        AEADId(int(data["aead_id"]))
    )

    # le stringhe nei test vectors contengono due caratteri esadecimali per ogni byte
    # quindi stringhe di 64 caratteri ad es., sono in realtà 32 bytes una volta decodificate
    my_sk = suite_r.kem.deserialize_private_key(bytes.fromhex(data["skRm"]))
    my_pk = suite_r.kem.deserialize_public_key(bytes.fromhex(data["pkRm"]))
    sender_pk = suite_r.kem.deserialize_public_key(bytes.fromhex(data["pkEm"]))
    enc = bytes.fromhex(data["enc"])
    
    psk = bytes.fromhex(data["psk"]) if "psk" in data else b""
    psk_id = bytes.fromhex(data["psk_id"]) if "psk_id" in data else b""
    info = bytes.fromhex(data["info"]) if "info" in data else b""
    aad = bytes.fromhex(data["aad"]) if "aad" in data else b""    
    ct = bytes.fromhex(data["ct"]) if "ct" in data else b""

    receiving = suite_r.create_recipient_context(enc, my_sk, info, None, psk, psk_id)

    plaintext = receiving.open(ct, aad).decode()
    original_plain_text = bytes.fromhex(data["pt"]).decode()
    print(plaintext)
    print(plaintext == original_plain_text)
