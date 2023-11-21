from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

kemID = KEMId.DHKEM_P256_HKDF_SHA256
kdfID = KDFId.HKDF_SHA256
aeadID = AEADId.CHACHA20_POLY1305

# Identificativo di una chiave. Questo perché jwk restituisce un insieme di chiavi. kty identifica quale prendere
kid = "01"
# Tipo di algoritmo usato con la chiave.
# EC = elliptic curve
# OKP = altro algoritmo
kty = "EC"
# Parametro per EC, indica il numero di bit per il numero primo utilzzato in EC
crv = "P-256"

# Coordinate di un qualche punto per EC
# Il numero di bytes è collegato al crv scelto:
#   "P-256" -> 32 bytes
#   "P-384" -> 48 bytes
#   "P-521" -> 66 bytes
x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"

# Parametro per RSA deve avere la stessa lunghezza di x e y.
# d è utilizzata per la generazione di chiave privata.
# d, x e y sono fra loro collegate non si possono scegliere a caso
d = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"

# The sender side:
suite_s = CipherSuite.new(
    kemID, kdfID, aeadID
)

# The recipient side:
suite_r = CipherSuite.new(
    kemID, kdfID, aeadID
)

# con d la chiave restituita è della classe EllipticCurvePublicKey
pkr = KEMKey.from_jwk(  # from_pem is also available.
    {
        "kid": kid,
        "kty": kty,
        "crv": crv,
        "x": x,
        "y": y
    }
)
print(pkr.to_public_bytes)

enc, sender = suite_s.create_sender_context(pkr)
ct = sender.seal(b"Messaggio sicuro!")

# con d la chiave restituita è della classe EllipticCurvePrivateKey
skr = KEMKey.from_jwk(
    {
        "kid": kid,
        "kty": kty,
        "crv": crv,
        "x": x,
        "y": y,
        "d": d
    }
)
recipient = suite_r.create_recipient_context(enc, skr)
pt = recipient.open(ct)

print(pt)

assert pt == b"Messaggio sicuro!"

# deriving a KEMKeyPair
keypair = suite_s.kem.derive_key_pair(b"some_ikm_bytes_used_for_key_derivation")


def send_message(message, public_key_receiver):
    pass