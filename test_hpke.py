import json
import sys
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMInterface
from pyhpke.kem import KEM
from pyhpke.kem_key import KEMKey


f = open('test_data.json')
test_data = json.load(f)
test_data = test_data["test1"] # change test vector here
mode = test_data["mode"]
print("Mode: " + str(mode))

kemID = int(test_data["kem_id"]) if "kem_id" in test_data else  16
kdfID = int(test_data["kdf_id"]) if "kdf_id" in test_data else 1
aeadID = int(test_data["aead_id"]) if "aead_id" in test_data else 3

info = test_data["info"].encode() if "info" in test_data else b""
psk = test_data["psk"].encode() if "psk" in test_data else b""
psk_id = test_data["psk_id"].encode() if "psk_id" in test_data else b""
sender_ikm = test_data["ikmE"].encode() if "ikmE" in test_data else b""
receiver_ikm = test_data["ikmR"].encode() if "ikmR" in test_data else b""
aad = test_data["aad"].encode() if "aad" in test_data else b""
pt = test_data["pt"] if "pt" in test_data else ""
#ct = test_data["ct"] if "ct" in test_data else ""

suite = CipherSuite.new(
    KEMId(kemID),
    KDFId(kdfID),
    AEADId(aeadID)
)

keys_prova = suite.kem.derive_key_pair(sender_ikm)
sender_sk = keys_prova.private_key
sender_pk = keys_prova.public_key
    
keys_prova = suite.kem.derive_key_pair(receiver_ikm)
receiver_sk = keys_prova.private_key
receiver_pk = keys_prova.public_key

if mode == 0:
    sender_sk = None
    sender_pk = None
    psk = b""
    psk_id = b""
elif mode == 1:
    sender_sk = None
    sender_pk = None
elif mode == 2:
    psk = b""
    psk_id = b""
elif mode == 3:
    pass
else:
    sys.exit("Mode not supported")

enc, sending = suite.create_sender_context(receiver_pk, info, sender_sk, psk, psk_id)
ciphertext = sending.seal(pt.encode(), aad)

#if ciphertext == ct.encode():
#   print("OK ENCRPYTION")
    
receiving = suite.create_recipient_context(enc, receiver_sk, info, sender_pk, psk, psk_id)
plaintext = receiving.open(ciphertext, aad).decode()

if plaintext == pt:
    print("OK DECRYPTION")
#else:
#    print("Plaintext modified")


