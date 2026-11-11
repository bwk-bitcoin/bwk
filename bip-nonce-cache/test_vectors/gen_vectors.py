#!/usr/bin/env python3
"""Generate the nonce cache test vectors.

Usage: gen_vectors.py <path to the bips repository's bip-0327 directory>

The nonce generation and MuSig2 signing come from the BIP-0327 reference
implementation (bip-0327/reference.py).
"""

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import reference as musig  # noqa: E402

OUT = Path(__file__).resolve().parent


def h(label):
    return hashlib.sha256(label.encode()).digest()


def ser32(i):
    return i.to_bytes(4, "big")


def seed(secret, i, j):
    return musig.tagged_hash("BIPXXXX_NONCE_SEED", secret + ser32(i) + ser32(j))


def session_ref(secret):
    return musig.tagged_hash("BIPXXXX_SESSION_REF", secret)[:4]


def cached_nonce(secret, i, j, sk):
    pk = musig.individual_pk(sk)
    secnonce, pubnonce = musig.nonce_gen_internal(seed(secret, i, j), sk, pk, None, None, None)
    return pk, bytes(secnonce), pubnonce


def write(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2) + "\n")


def seed_vectors():
    cases = []
    for secret_label, i, j in [("secret 0", 0, 0), ("secret 0", 1, 0), ("secret 0", 0, 1),
                               ("secret 0", 254, 15), ("secret 1", 0, 0)]:
        secret = h(secret_label)
        cases.append({"secret": secret.hex(), "i": i, "j": j, "seed": seed(secret, i, j).hex()})
    write("seed.json", cases)


def session_ref_vectors():
    cases = []
    for label in ["secret 0", "secret 1"]:
        secret = h(label)
        cases.append({"secret": secret.hex(), "ref": session_ref(secret).hex()})
    write("session_ref.json", cases)


def nonce_vectors():
    cases = []
    secret = h("secret 0")
    for sk_label, i, j, comment in [
        ("key A", 0, 0, ""),
        ("key A", 1, 0, "next input"),
        ("key A", 0, 1, "next key expression"),
        ("key B", 0, 0, "another key at the same (i, j)"),
    ]:
        sk = h(sk_label)
        pk, secnonce, pubnonce = cached_nonce(secret, i, j, sk)
        cases.append({"secret": secret.hex(), "i": i, "j": j, "sk": sk.hex(), "pk": pk.hex(),
                      "secnonce": secnonce.hex(), "pubnonce": pubnonce.hex(), "comment": comment})
    write("nonce.json", cases)


KEY_EXPRESSION = re.compile(r"musig\([^)]*\)(?:/[^,)}]*)?|@\d+(?:/[^,)}]*)?")


def key_expression_indexes(policy, signer_keys):
    out = []
    j = 0
    for m in KEY_EXPRESSION.finditer(policy):
        keys = {int(k) for k in re.findall(r"@(\d+)", m.group(0))}
        if keys & signer_keys:
            out.append({"expression": m.group(0), "j": j})
            j += 1
    return out


def key_expression_vectors():
    cases = []
    for policy, signer_keys in [
        ("tr(musig(@0,@1)/<0;1>/*,{pk(@2/<0;1>/*),and_v(v:pk(@0/<2;3>/*),"
         "multi_a(1,@3/<0;1>/*,@1/<2;3>/*))})", {0}),
        ("tr(musig(@0,@1)/<0;1>/*,{pk(@2/<0;1>/*),and_v(v:pk(@0/<2;3>/*),"
         "multi_a(1,@3/<0;1>/*,@1/<2;3>/*))})", {1}),
        ("tr(@0/<0;1>/*,{pk(@1/<0;1>/*),pk(@0/<2;3>/*)})", {0}),
        ("tr(@0/<0;1>/*,pk(musig(@1,@2)/<0;1>/*))", {0}),
        ("tr(@0/<0;1>/*,pk(musig(@1,@2)/<0;1>/*))", {2}),
        ("wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:pk(@2/<0;1>/*),older(52560))))", {1}),
        ("wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:pk(@2/<0;1>/*),older(52560))))", {2}),
        ("sh(wsh(sortedmulti(2,@0/**,@1/**,@2/**)))", {0, 2}),
    ]:
        cases.append({"policy": policy, "signer_keys": sorted(signer_keys),
                      "key_expressions": key_expression_indexes(policy, signer_keys)})
    write("key_expression_index.json", cases)


def psbt_field_vectors():
    cases = []
    for id_label, secret_label in [("session 0", "secret 0"), ("session 1", "secret 1")]:
        session_id = h(id_label)[:4]
        ref = session_ref(h(secret_label))
        value = session_id + ref
        cases.append({"session_id": session_id.hex(), "ref": ref.hex(),
                      "key": (bytes([1, 0x09])).hex(),
                      "value": (bytes([len(value)]) + value).hex()})
    write("psbt_field.json", cases)


def musig2_vectors():
    secret = h("secret 0")
    i, j = 0, 0
    sk_a, sk_b = h("key A"), h("key B")
    pk_a, secnonce_a, pubnonce_a = cached_nonce(secret, i, j, sk_a)
    pk_b = musig.individual_pk(sk_b)
    rand_b = h("rand B")
    secnonce_b, pubnonce_b = musig.nonce_gen_internal(rand_b, sk_b, pk_b, None, None, None)
    pubkeys = [pk_a, pk_b]
    msg = h("message")
    aggnonce = musig.nonce_agg([pubnonce_a, pubnonce_b])
    ctx = musig.SessionContext(aggnonce, pubkeys, [], [], msg)
    psig_a = musig.sign(bytearray(secnonce_a), sk_a, ctx)
    psig_b = musig.sign(secnonce_b, sk_b, ctx)
    assert musig.partial_sig_verify(psig_a, [pubnonce_a, pubnonce_b], pubkeys, [], [], msg, 0)
    assert musig.partial_sig_verify(psig_b, [pubnonce_a, pubnonce_b], pubkeys, [], [], msg, 1)
    sig = musig.partial_sig_agg([psig_a, psig_b], ctx)
    aggpk = musig.get_xonly_pk(musig.key_agg(pubkeys))
    assert musig.schnorr_verify(msg, aggpk, sig)
    write("musig2_signing.json", [{
        "comment": "signer A uses its cached nonce, signer B a BIP-0327 NonceGen nonce; "
                   "no tweaks",
        "secret_a": secret.hex(), "i": i, "j": j,
        "sk_a": sk_a.hex(), "sk_b": sk_b.hex(),
        "pubkeys": [pk.hex() for pk in pubkeys],
        "rand_b": rand_b.hex(),
        "pubnonce_a": pubnonce_a.hex(), "pubnonce_b": pubnonce_b.hex(),
        "aggnonce": aggnonce.hex(), "msg": msg.hex(),
        "psig_a": psig_a.hex(), "psig_b": psig_b.hex(),
        "aggpk": aggpk.hex(), "sig": sig.hex(),
    }])


if __name__ == "__main__":
    seed_vectors()
    session_ref_vectors()
    nonce_vectors()
    key_expression_vectors()
    psbt_field_vectors()
    musig2_vectors()
