import json

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyInterface
from pyhpke.keys.x25519_key import X25519Key
from pyhpke.kem import KEM
from pyhpke.kem_key import KEMKey

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
    #keypair = suite_r.kem.derive_key_pair(ikm)

    #my_pk = keypair.public_key
    #my_sk = keypair.private_key

    # get sender public key
    #sender_ikm = data["ikmE"].encode()
    #sender_keypair = suite_r.kem.derive_key_pair(sender_ikm)

    #sender_pk = sender_keypair.public_key

    # get information
    my_sk = data["skRm"].encode()
    my_pk = data["pkRm"].encode()
    sender_pk = data["pkEm"].encode()
    enc = data["enc"].encode() # PROBLEMA: enc dovrebbe essere in public_bytes
    
    keys = KEM(KEMId(int(data["kem_id"])))
    keys_prova = keys.derive_key_pair(ikm)
    #my_sk = keys.deserialize_private_key(my_sk)
    #my_pk = keys.deserialize_public_key(my_pk)
    my_sk = keys_prova.private_key
    my_pk = keys_prova.public_key
    
    
    psk = b""
    psk_id = b""
    info = data["info"].encode()
    aad = data["aad"].encode()
    ct = data["ct"]

    receiving = suite_r.create_recipient_context(enc, my_sk, info, None, psk, psk_id)

    in_message = receiving.open(ct, aad).decode()

    print(in_message)
