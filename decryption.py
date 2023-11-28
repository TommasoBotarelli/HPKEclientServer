import json

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyInterface
from pyhpke.keys.x25519_key import X25519Key

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

    ikm = data["ikmR"].encode()
    keypair = suite_r.kem.derive_key_pair(ikm)

    my_pk = keypair.public_key
    my_sk = keypair.private_key

    # get sender public key
    sender_ikm = data["ikmE"].encode()
    sender_keypair = suite_r.kem.derive_key_pair(sender_ikm)

    sender_pk = sender_keypair.public_key

    # get information
    psk = b""
    psk_id = b""
    info = data["info"].encode()
    aad = data["aad"].encode()
    enc = data["enc"].encode()
    print(enc)
    ct = data["ct"].encode()

    receiving = suite_r.create_recipient_context(enc, my_sk, info, None, psk, psk_id)

    in_message = receiving.open(ct, aad).decode()

    print(in_message)
