import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyPair

keys_array = ["kem_id", "aead_id", "kdf_id", "info", "pkSm", "ct", "enc", "aad", "psk", "psk_id"]

f = open('encryption_info.json')
v = json.load(f)

info_dict = {}

for key in keys_array:
    if key in v:
        info_dict[key] = v[key]

suite = CipherSuite.new(KEMId(int(v["kem_id"])), KDFId(int(v["kdf_id"])), AEADId(int(v["aead_id"])))

ikm = bytes.fromhex(v["ikmE"])

keypair = suite.kem.derive_key_pair(ikm)

my_pk = keypair.public_key
my_sk = keypair.private_key

info_dict["pkSm"] = bytes.hex(my_pk.to_public_bytes())

pkr = suite.kem.deserialize_public_key(bytes.fromhex(v["pkRm"]))
info = bytes.fromhex(v["info"])
psk = bytes.fromhex(v["psk"]) if "psk" in v else b""
psk_id = bytes.fromhex(v["psk_id"]) if "psk_id" in v else b""
eks = None if "eks" not in v else v["eks"]

enc, sender = suite.create_sender_context(pkr, info, my_sk, psk, psk_id, eks)

info_dict["enc"] = bytes.hex(enc)

if v["aead_id"] != 0xFFFF:
    message = input('Scrivi messaggio: ').encode()
    aad = bytes.fromhex(v["aad"])
    sealed = sender.seal(message, aad)
    info_dict["ct"] = bytes.hex(sealed)

with open("encrypted_info.json", "w") as file:
    json.dump(info_dict, file)

print("encrypted_info.json salvato")
