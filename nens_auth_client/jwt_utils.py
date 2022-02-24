import json
import base64


def decode_jwt(token):
    """Decode a JWT without checking its signature"""
    if not token:
        return
    # JWT consists of {header}.{payload}.{signature}
    try:
        _, payload, _ = token.split(".")
    except ValueError:
        return "token is not a JWT"

    # JWT should be padded with = (base64.b64decode expects this)
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.b64decode(payload))
