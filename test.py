#!/usr/bin/env python3
import base64
import json
import zlib

import base45
import cbor2

HC1_STRING = "HC1:6BFOXNMG2N9HZBPYHQ3D69SO5D6%9L60JODJS4L:P:R8LCDO%0AA3BI16TMVMJ3$C*2AL+J7AJENS:NK7VCECM:MQ0FE%JC5Y479D/*8G.CV3NV3OVLD86J:KE2HF86GX2BTLHA9A86GNY8XOIROBZQMQOB9MEBED:KE87BMH:8DZYK%KNU9O%UL75E2*KH42$T8CRJ.V89:GF-K8JVT$8LQNYVKY8$IV7/05T8::S%MV6J3$IV747ZIV7WN3$V8U8IVNVG/U85VCEWVLTVUPVFCN.9FS0JE/8L-AXS8LMFLIF%57LSV$TFVZK%57NTV1IN1$VNVGHVVFWC9UVGYG8UVFGV%TFI3J5XKL0A/S3VGKJN5QN8$SAC71EN/6JU%8.YI3T8O8FPVNRT2OMNR3BBSNTGVCRNY83%%GEO0/933OJOLN4RVQJ0.H9PBL7EPYDK3I6.ROIAW231W/PUA16UEZ3IK6MABH53FW5909VRR91%MS*H9DMNCTNX7P0VYJH5H7+SR/PTT89E7:TF3.EN$UF$B42SK72/QHR11U0VAY3C9JTB4MVVIB45TJ1XPU0U%*SBMRUS4*C5V.O+HEYBS930.80T5"


def bytes_to_json_safe(obj):
    """Convert bytes in nested structures to base64url so json.dumps works."""
    if isinstance(obj, bytes):
        return {"_b64": base64.urlsafe_b64encode(obj).decode("ascii").rstrip("=")}
    if isinstance(obj, dict):
        return {k: bytes_to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [bytes_to_json_safe(v) for v in obj]
    return obj

def unwrap_cbor_tags(x):
    """Repeatedly unwrap CBOR tags (especially tag 18 for COSE_Sign1)."""
    while isinstance(x, cbor2.CBORTag):
        x = x.value
    return x

def decode_hc1_to_json(hc1: str):
    if not hc1.startswith("HC1:"):
        raise ValueError("Input must start with 'HC1:'")



    # 1) strip HC1:
    data = hc1[4:]

    # 2) Base45 decode -> zlib-compressed bytes
    compressed = base45.b45decode(data)

    # 3) zlib decompress -> CBOR (COSE_Sign1)
    cose_cbor = zlib.decompress(compressed)

    # 4) CBOR decode
    cose = cbor2.loads(cose_cbor)
    cose = unwrap_cbor_tags(cose)

    # COSE_Sign1 should be a 4-item list: [protected, unprotected, payload, signature]
    if not (isinstance(cose, list) and len(cose) == 4):
        raise ValueError("Not a valid COSE_Sign1 structure")

    protected_bstr, unprotected_map, payload_bstr, signature_bstr = cose

    # decode protected headers (CBOR-encoded bstr)
    protected_headers = {}
    if protected_bstr:
        protected_headers = cbor2.loads(protected_bstr)

    # payload is a CBOR map (CWT). Decode it.
    payload = {}
    if payload_bstr:
        payload = cbor2.loads(payload_bstr)

    # Extract HCERT from CWT payload: -260 -> {1: <hcert>}
    hcert = None
    if -260 in payload:
        container = payload[-260]
        if isinstance(container, dict) and 1 in container:
            hcert = container[1]

    # Optional: extract KID from headers (label 4)
    kid = None
    kid_bytes = protected_headers.get(4) or (unprotected_map.get(4) if isinstance(unprotected_map, dict) else None)
    if kid_bytes:
        if isinstance(kid_bytes, bytes):
            kid = base64.urlsafe_b64encode(kid_bytes).decode("ascii").rstrip("=")
        elif isinstance(kid_bytes, str):
            kid = kid_bytes

    result = {
        "cose": {
            "protected": bytes_to_json_safe(protected_headers),
            "unprotected": bytes_to_json_safe(unprotected_map) if isinstance(unprotected_map, dict) else unprotected_map,
            "kid_b64": kid,
            "signature": bytes_to_json_safe(signature_bstr),
        },
        "payload": bytes_to_json_safe(payload),
        "hcert": bytes_to_json_safe(hcert) if hcert is not None else None,
    }

    return result

if __name__ == "__main__":
    obj = decode_hc1_to_json(HC1_STRING)
    print(json.dumps(obj, indent=2, ensure_ascii=False))
