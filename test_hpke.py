import json
import sys
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyInterface, KEMKeyPair
from pyhpke.kem import KEM
from pyhpke.kem_key import KEMKey
from random import randrange

n_test = 4
f = open('decryption/test_data.json')
test_data = json.load(f)
i = randrange(n_test) + 1 
test = "test" + str(i)
test_data = test_data[test]
mode = test_data["mode"]
print("Mode: " + str(mode))

kemID = test_data["kem_id"] if "kem_id" in test_data else  16
kdfID = test_data["kdf_id"] if "kdf_id" in test_data else 1
aeadID = test_data["aead_id"] if "aead_id" in test_data else 3

info = bytes.fromhex(test_data["info"]) if "info" in test_data else b""
psk = bytes.fromhex(test_data["psk"]) if "psk" in test_data else b""
psk_id = bytes.fromhex(test_data["psk_id"]) if "psk_id" in test_data else b""
aad = bytes.fromhex(test_data["aad"]) if "aad" in test_data else b""
pt = bytes.fromhex(test_data["pt"]) if "pt" in test_data else ""
ct = bytes.fromhex(test_data["ct"]) if "ct" in test_data else ""
enc = bytes.fromhex(test_data["enc"]) if "enc" in test_data else ""

suite = CipherSuite.new(
    KEMId(kemID),
    KDFId(kdfID),
    AEADId(aeadID)
)

pke = suite.kem.deserialize_public_key(bytes.fromhex(test_data["pkEm"]))
ske = suite.kem.deserialize_private_key(bytes.fromhex(test_data["skEm"]))
eks = KEMKeyPair(ske, pke)

pkr = suite.kem.deserialize_public_key(bytes.fromhex(test_data["pkRm"]))
skr = suite.kem.deserialize_private_key(bytes.fromhex(test_data["skRm"]))

sks = None
pks = None
if "skSm" in test_data and "pkSm" in test_data:
    sks = suite.kem.deserialize_private_key(bytes.fromhex(test_data["skSm"]))
    pks = suite.kem.deserialize_public_key(bytes.fromhex(test_data["pkSm"]))

# Check ephemereal keys
ikme = bytes.fromhex(test_data["ikmE"])
ikme_keypair = suite.kem.derive_key_pair(ikme)
assert ikme_keypair.private_key.to_private_bytes() == ske.to_private_bytes()
assert ikme_keypair.public_key.to_public_bytes() == pke.to_public_bytes()

# Check receiver keys
ikmr = bytes.fromhex(test_data["ikmR"])
ikmr_keypair = suite.kem.derive_key_pair(ikmr)
assert ikmr_keypair.private_key.to_private_bytes() == skr.to_private_bytes()
assert ikmr_keypair.public_key.to_public_bytes() == pkr.to_public_bytes()

# Check sender keys
if "skSm" in test_data and "pkSm" in test_data:
    ikms = bytes.fromhex(test_data["ikmS"])
    ikms_keypair = suite.kem.derive_key_pair(ikms)
    assert ikms_keypair.private_key.to_private_bytes() == sks.to_private_bytes()
    assert ikms_keypair.public_key.to_public_bytes() == pks.to_public_bytes()

enc_key, sending = suite.create_sender_context(pkr, info, sks, psk, psk_id, eks)
if enc_key == enc:
    print("OK ENC")
else:
    print("Error in enc derivation")
   
ciphertext = sending.seal(pt, aad)
pt = pt.decode()
if ciphertext == ct:
    print("OK ENCRPYTION")
else:
    print("Different ciphertext") 
    
receiving = suite.create_recipient_context(enc_key, skr, info, pks, psk, psk_id)
plaintext = receiving.open(ciphertext, aad).decode()
print("Plaintext: "+plaintext)
print("Original plaintext: "+pt)
if plaintext == pt:
    print("=> OK DECRYPTION")
else:
    print("Error in decryption")
