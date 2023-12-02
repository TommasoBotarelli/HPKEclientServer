import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyPair
import random

if __name__ == "__main__":
    # array delle chiavi da introdurre nel json in uscita
    keys_array = ["kem_id", "aead_id", "kdf_id", "info", "pkSm", "ct", "enc", "aad", "psk", "psk_id"]

    # carico il file json con le informazioni per effettuare l'encryption
    f = open('encryption_info.json')
    v = json.load(f)

    n_random = random.randint(0, len(list(v.keys()))-1)
    print(f"Ho selezionato la configurazione {list(v.keys())[n_random]}")
    v = v[list(v.keys())[n_random]]

    info_dict = {}

    # copio nel dizionario di uscita le modalità di configurazione necessarie per effettuare la decryption
    for key in keys_array:
        if key in v:
            info_dict[key] = v[key]

    # creo la suite
    suite = CipherSuite.new(KEMId(int(v["kem_id"])), KDFId(int(v["kdf_id"])), AEADId(int(v["aead_id"])))

    # recupero ikm
    ikm = bytes.fromhex(v["ikmE"])

    # genero una coppia di chiavi pubblico privata
    keypair = suite.kem.derive_key_pair(ikm)

    my_pk = keypair.public_key
    my_sk = keypair.private_key

    # recupero la chiave pubblica a cui mandare il messaggio
    info_dict["pkSm"] = bytes.hex(my_pk.to_public_bytes())

    # recupero le informazioni necessarie per effettuare l'encryption
    pkr = suite.kem.deserialize_public_key(bytes.fromhex(v["pkRm"]))
    info = bytes.fromhex(v["info"])
    psk = bytes.fromhex(v["psk"]) if "psk" in v else b""
    psk_id = bytes.fromhex(v["psk_id"]) if "psk_id" in v else b""
    eks = None if "eks" not in v else v["eks"]

    # creo il contesto
    enc, sender = suite.create_sender_context(pkr, info, my_sk, psk, psk_id, eks)

    info_dict["enc"] = bytes.hex(enc)

    # effettuo l'encryption
    if v["aead_id"] != 0xFFFF:
        message = input('Scrivi messaggio: ')
        pt = bytes.hex(message.encode())
        info_dict["pt"] = pt
        aad = bytes.fromhex(v["aad"])
        sealed = sender.seal(message.encode(), aad)
        info_dict["ct"] = bytes.hex(sealed)

    # salvo i risultati sul json
    with open("encrypted_info.json", "w") as file:
        json.dump(info_dict, file)

    print("encrypted_info.json salvato")
