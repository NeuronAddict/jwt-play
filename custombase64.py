import base64


def base64url_decode(encoded_bytes):
    rem = len(encoded_bytes) % 4

    if rem > 0:
        encoded_bytes += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(encoded_bytes)


def base64url_encode(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).replace(b'=', b'')