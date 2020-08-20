__version__ = "2.0.0"
__version_info__ = (int(v) for v in __version__.split("."))

import base64
import struct

CRC24_INIT = 0xB704CE
CRC24_POLY = 0x1864CFB


class BadChecksumError(Exception):
    pass


def ord_safe(ch):
    if isinstance(ch, int):
        return ch
    return ord(ch)


def crc24(data):
    crc = CRC24_INIT
    for byte in data:
        crc ^= ord_safe(byte) << 16
        for _i in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= CRC24_POLY
    return crc & 0xFFFFFF


def armor(data, versioned=True):
    """
    Returns a string in ASCII Armor format, for the given binary data. The
    output of this is compatiple with pgcrypto's armor/dearmor functions.
    """
    template = "-----BEGIN PGP MESSAGE-----\n%(headers)s%(body)s\n=%(crc)s\n-----END PGP MESSAGE-----"
    body = base64.b64encode(data)
    # The 24-bit CRC should be in big-endian, strip off the first byte (it's already masked in crc24).
    crc = base64.b64encode(struct.pack(">L", crc24(data))[1:])
    return template % {
        "headers": "Version: django-pgcrypto %s\n\n" % __version__ if versioned else "\n",
        "body": body.decode("ascii"),
        "crc": crc.decode("ascii"),
    }


def dearmor(text, verify=True):
    """
    Given a string in ASCII Armor format, returns the decoded binary data.
    If verify=True (the default), the CRC is decoded and checked against that
    of the decoded data, otherwise it is ignored. If the checksum does not
    match, a BadChecksumError exception is raised.
    """
    lines = text.strip().split("\n")
    data_lines = []
    check_data = None
    started = False
    in_body = False
    for line in lines:
        if line.startswith("-----BEGIN"):
            started = True
        elif line.startswith("-----END"):
            break
        elif started:
            if in_body:
                if line.startswith("="):
                    # Once we get the checksum data, we're done.
                    check_data = line[1:5].encode("ascii")
                    break
                else:
                    # This is part of the base64-encoded data.
                    data_lines.append(line)
            else:
                if line.strip():
                    # This is a header line, which we basically ignore for now.
                    pass
                else:
                    # The data starts after an empty line.
                    in_body = True
    b64_str = "".join(data_lines)
    # Python 3's b64decode expects bytes, not a string. We know base64 is ASCII, though.
    data = base64.b64decode(b64_str.encode("ascii"))
    if verify and check_data:
        # The 24-bit CRC is in big-endian, so we add a null byte to the beginning.
        crc = struct.unpack(">L", b"\0" + base64.b64decode(check_data))[0]
        if crc != crc24(data):
            raise BadChecksumError()
    return data


def unpad(text, block_size):
    """
    Takes the last character of the text, and if it is less than the block_size,
    assumes the text is padded, and removes any trailing zeros or bytes with the
    value of the pad character. See http://www.di-mgt.com.au/cryptopad.html for
    more information (methods 1, 3, and 4).
    """
    end = len(text)
    if end == 0:
        return text
    padch = ord_safe(text[end - 1])
    if padch > block_size:
        # If the last byte value is larger than the block size, it's not padded.
        return text
    while end > 0 and ord_safe(text[end - 1]) in (0, padch):
        end -= 1
    return text[:end]


def pad(text, block_size, zero=False):
    """
    Given a text string and a block size, pads the text with bytes of the same value
    as the number of padding bytes. This is the recommended method, and the one used
    by pgcrypto. See http://www.di-mgt.com.au/cryptopad.html for more information.
    """
    num = block_size - (len(text) % block_size)
    ch = b"\0" if zero else chr(num).encode("latin-1")
    return text + (ch * num)


def aes_pad_key(key):
    """
    AES keys must be either 16, 24, or 32 bytes long. If a key is provided that is not
    one of these lengths, pad it with zeroes (this is what pgcrypto does).
    """
    if len(key) in (16, 24, 32):
        return key
    if len(key) < 16:
        return pad(key, 16, zero=True)
    elif len(key) < 24:
        return pad(key, 24, zero=True)
    elif len(key) < 32:
        return pad(key, 32, zero=True)
    else:
        return key[:32]
