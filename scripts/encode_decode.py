import os
import subprocess
import re
from io import BytesIO

import base64
import binascii
import codecs
import tarfile
import gzip
import bz2
import lzma
import lz4.frame
import zstd
import snappy
import zlib

from rich import print


ENCODING_MULTIFILE = False
YARA_FILENAME = "susp_sites_encoded.yar"
RULE_VERSION = "1.2"
URLS = [
    "cdn.discordapp.com/attachments",
    "https://discord.com/api",
    "https://drive.google.com",
    "ngrok.io",
    "https://pastebin.com",
    "https://filebin.net",
    "https://file.io",
    "https://filebin.net",
    "https://paste.ee",
    "https://transfer.sh",
    "https://anonfiles.com",
    "https://mega.nz",
    "https://gofile.io",
    "https://ufile.io",
    "https://dropmefiles.com",
    "https://file.io",
    "https://sendspace.com",
    "https://bayfiles.com",
    "https://wetransfer.com",
    "https://uploadfiles.io",
    "https://share.dmca.gripe",
    "https://temp.sh",
    "https://api.ipify.org",
    "https://justpaste.it",
    "https://ctrlv.it",
    "https://hastebin.com",
    "https://p.ip.fi",
    "https://filepizza.com",
    "https://mixdrop.co",
    "https://rentry.co",
    "https://toptal.com/developers/hastebin",
    "https://0bin.net",
    "https://firefox.send",
    "https://we.tl",
    "https://dfile.space",
    "https://easyupload.io",
    "https://0x0.st",
    "https://controlc.com",
    "https://rentry.co",
    "https://ghostbin.com",
    "https://zerobin.net",
    "https://anonfile.com",
    "https://bayfiles.com",
    "https://dropmefiles.com",
]

# Remove duplicate URLs
URLS = list(set(URLS))


def compress_string(data: str) -> dict:
    """Compress in various formats."""
    encoded = {}
    with BytesIO(data.encode()) as input_buffer:
        formats = [
            ("gz", gzip.compress),
            (
                "bz2",
                bz2.compress,
            ),  # Also covers Brotli
            (
                "lzma",
                lzma.compress,
            ),  # Also covers xz
            ("deflate", zlib.compress),
            ("zlib", zlib.compress),
            ("zlib", zlib.compress),
            ("lz4", lz4.frame.compress),  # LZ4 is a frame format
            ("zstd", zstd.compress),
            ("snappy", snappy.compress),
            ("rar", compress_with_rar),
            # ("ppmparser", ppmparser.compress),  # too obscure
        ]

        if ENCODING_MULTIFILE:
            formats.extend(
                [
                    (
                        "tar_gz",
                        lambda data: gzip.compress(
                            tarfile.open(
                                fileobj=BytesIO(data), mode="w"
                            ).fileobj.getvalue()
                        ),
                    ),
                    (
                        "tar_bz2",
                        lambda data: bz2.compress(
                            tarfile.open(
                                fileobj=BytesIO(data), mode="w"
                            ).fileobj.getvalue()
                        ),
                    ),
                    (
                        "tar_xz",
                        lambda data: lzma.compress(
                            tarfile.open(
                                fileobj=BytesIO(data), mode="w"
                            ).fileobj.getvalue()
                        ),
                    ),
                ]
            )
        
        for compression, compressor in formats:
            with BytesIO() as output_buffer:
                compressed_data = compressor(input_buffer.getvalue())
                output_buffer.write(compressed_data)
                encoded[compression] = (
                    "{"
                    + " ".join(f"{byte:02X}" for byte in output_buffer.getvalue())
                    + "}"
                )

    return encoded


def encode_string(string: str) -> dict:
    """Encode a string in various formats for YARA rules."""

    encoded = {
        "base64": base64.b64encode(string.encode()).decode(),
        "hex": binascii.hexlify(string.encode()).decode(),
        "rot13": codecs.encode(string, "rot_13"),
        "base32": base64.b32encode(string.encode()).decode(),
        "base16": base64.b16encode(string.encode()).decode(),
        "base85": base64.b85encode(string.encode()).decode(),
        "ascii85": base64.a85encode(string.encode()).decode(),
        "uu": base64.encodebytes(string.encode()).decode(),
    }

    # Remove the trailing newline from unix-to-unix encoding
    encoded["uu"] = encoded["uu"].replace("\n", "")
    return encoded


def compress_with_rar(data):
    """NOTE: tempfile will not work"""
    with open("temp.txt", "wb") as file:
        file.write(data)
    subprocess.run(["rar", "a", "temp.rar", "temp.txt"])
    with open("temp.rar", "rb") as file:
        compressed_data = file.read()

    os.remove("temp.txt")
    os.remove("temp.rar")

    return compressed_data


def encrypt_string(string: str) -> dict:
    def rot47(char):
        if 33 <= ord(char) <= 126:
            return chr(33 + ((ord(char) + 14) % 94))
        return char

    def rot5(char):
        if char.isdigit():
            return str((int(char) + 5) % 10)
        return char

    def rot18(char):
        if char.isdigit():
            return str((int(char) + 2) % 10)
        return char

    string_has_no_digits = not any([char.isdigit() for char in string])
    string_has_no_ordinals = not any([33 <= ord(char) <= 126 for char in string])

    encrypted = {}
    if not string_has_no_digits:
        encrypted["rot5"] = "".join([rot5(char) for char in string])
        encrypted["rot18"] = "".join([rot18(char) for char in string])
    if not string_has_no_ordinals:
        encrypted["rot47"] = "".join([rot47(char) for char in string])
        # encrypted["affine"] = "".join([chr((ord(char) * 5 + 8) % 256) for char in string])
        encrypted["substitution"] = "".join(
            [
                chr(
                    ord(char)
                    if not char.isalpha()
                    else ord("a") + (ord(char) - ord("a") + 3) % 26
                )
                for char in string
            ]
        )
        # encrypted["atbash"] = "".join([chr(255 - ord(char)) for char in string])
        encrypted["caesar"] = "".join([chr((ord(char) + 3) % 256) for char in string])

    return encrypted


def convert_urls(urls):
    output = []
    case_insensitive_encodings = ["base64", "hex", "base32", "base16", "url", "uu"]
    get_case_modifier = lambda encoding: (
        " nocase" if encoding in case_insensitive_encodings else ""
    )

    def escape_chars(string):
        return re.sub(r'["\\\n\t\r\v]', lambda match: f"\\{match.group(0)}", string)

    cur_index = 0
    for url in urls:
        existing = set()
        output.append(f'    $site_{cur_index} = "{url}" nocase')
        
        compressed = compress_string(url)
        for compression, compressed_string in compressed.items():
            if compressed_string in existing:
                continue

            existing.add(compressed_string)
            output.append(
                f"    $site_{cur_index}_encoded_{compression} = {compressed_string}"
            )

        encoded = encode_string(url)
        for encoding, encoded_string in encoded.items():
            if encoded_string in existing:
                continue

            existing.add(encoded_string)
            encoded_string = escape_chars(encoded_string)
            output.append(
                f'    $site_{cur_index}_encoded_{encoding} = "{encoded_string}"{get_case_modifier(encoding)}'
            )

        encrypted = encrypt_string(url)
        for encryption, encrypted_string in encrypted.items():
            if encrypted_string in existing:
                continue

            existing.add(encrypted_string)
            encrypted_string = escape_chars(encrypted_string)
            output.append(
                f'    $site_{cur_index}_encoded_{encryption} = "{encrypted_string}"{get_case_modifier(encryption)}'
            )

        output.append("")
        cur_index += 1
    return output


def write_output_to_file(output, filename):
    with open(filename, "w") as file:
        file.write(yara_template_top)
        for line in output:
            file.write(f"{line}\n")
        file.write(yara_template_bottom)


yara_template_top = """
rule SUSP_Websites_In_Compressed_Data {
  meta:
    author = "christian-byrne"
    description = "Detects references to suspicious sites inside compressed or encoded data"
    organization = ""
"""
yara_template_top += f'    version = "{RULE_VERSION}"\n'
import time

yara_template_top += f'    date = "{time.strftime("%d.%m.%Y")}"\n'

yara_template_top += """    reference = "https://old.reddit.com/r/comfyui/comments/1dbls5n/psa_if_youve_used_the_comfyui_llmvision_node_from/"
    category = "C2"
    tags = "ComfyUI"
    severity = "high"
    license = "Unlicense"
    
  strings:
"""
yara_template_bottom = """  condition:
    any of them
}
"""

def try_decode_string(string, decode_func: callable):
    try:
        return decode_func(string)
    except Exception as e:
        return e.__class__.__name__


def decode_string(string):
    """Decodes string using every method outline in this script and returns a dictionary of the results."""
    result = {}
    result["base64"] = try_decode_string(string, base64.b64decode)
    result["hex"] = try_decode_string(string, binascii.unhexlify)
    result["rot13"] = try_decode_string(string, lambda s: codecs.encode(s, "rot_13"))
    result["base32"] = try_decode_string(string, lambda s: base64.b32decode(s))
    result["base16"] = try_decode_string(string, lambda s: base64.b16decode(s))
    result["base85"] = try_decode_string(string, lambda s: base64.b85decode(s))
    result["ascii85"] = try_decode_string(string, lambda s: base64.a85decode(s))
    result["uu"] = try_decode_string(string, lambda s: base64.decodebytes(s.encode()).decode())
    result["caeasar"] = try_decode_string(string, lambda s: "".join([chr((ord(char) - 3) % 256) for char in s]))
    result["zlib"] = try_decode_string(string, zlib.decompress)
    result["lzma"] = try_decode_string(string, lzma.decompress)
    result["lz4"] = try_decode_string(string, lz4.frame.decompress)
    result["zstd"] = try_decode_string(string, zstd.decompress)
    result["snappy"] = try_decode_string(string, snappy.decompress)
    result["bz2"] = try_decode_string(string, bz2.decompress)
    result["gzip"] = try_decode_string(string, gzip.decompress)
    result["rar"] = try_decode_string(string, lambda s: subprocess.run(["unrar", "e", "temp.rar"]).stdout)




    return result

from cryptography.fernet import Fernet
encoded_string_1 = "gAAAAABmEi6IMsOG7am-kCT2D3ZUBp__HoQlLHUbzsHsZnvfQ4eEwZKbtYZnvLZasGPp7mBh-GgJvs85cSz2qjf3qDiEVZ680AYK_GAD7-iMPwZYu86zmAd9JlThMvQkguHj40txpMtkEXHMOGHtpHF6OXx_xV_kxnQ4kcAumjdgTRmLG45xtcs42H3TOWEq5IIWbH_ZEL1VMrQhaxyZvmrx9KbNFfZ0WBRP46xhbuCScvJrxDvxIG4="
fernet_codec = Fernet("zfW7TU0Gc8JhJW2TWZ_RYa6Dy7ysMpsqKghWypHpERw=")
res_ = fernet_codec.decrypt(encoded_string_1).decode()

print(res_)
if __name__ == "__main__":
    output = convert_urls(URLS)
    write_output_to_file(output, YARA_FILENAME)
    print("Done writing encoded strings to file.")
    x = decode_string("gAAAAABmEi6IMsOG7am-kCT2D3ZUBp__HoQlLHUbzsHsZnvfQ4eEwZKbtYZnvLZasGPp7mBh-GgJvs85cSz2qjf3qDiEVZ680AYK_GAD7-iMPwZYu86zmAd9JlThMvQkguHj40txpMtkEXHMOGHtpHF6OXx_xV_kxnQ4kcAumjdgTRmLG45xtcs42H3TOWEq5IIWbH_ZEL1VMrQhaxyZvmrx9KbNFfZ0WBRP46xhbuCScvJrxDvxIG4=")
    x = decode_string(
        "zfW7TU0Gc8JhJW2TWZ_RYa6Dy7ysMpsqKghWypHpERw="
    )
    print(x)