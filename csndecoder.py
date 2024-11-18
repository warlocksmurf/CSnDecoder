import base64
import javaobj.v2 as javaobj
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import struct
import socket
import hashlib
import binascii
import re

dCodepages = {
    37: 'IBM EBCDIC US-Canada',
    437: 'OEM United States',
    500: 'IBM EBCDIC International',
    708: 'Arabic (ASMO 708)',
    709: 'Arabic (ASMO-449+, BCON V4)',
    710: 'Arabic - Transparent Arabic',
    720: 'Arabic (Transparent ASMO); Arabic (DOS)',
    737: 'OEM Greek (formerly 437G); Greek (DOS)',
    775: 'OEM Baltic; Baltic (DOS)',
    850: 'OEM Multilingual Latin 1; Western European (DOS)',
    852: 'OEM Latin 2; Central European (DOS)',
    855: 'OEM Cyrillic (primarily Russian)',
    857: 'OEM Turkish; Turkish (DOS)',
    858: 'OEM Multilingual Latin 1 + Euro symbol',
    860: 'OEM Portuguese; Portuguese (DOS)',
    861: 'OEM Icelandic; Icelandic (DOS)',
    862: 'OEM Hebrew; Hebrew (DOS)',
    863: 'OEM French Canadian; French Canadian (DOS)',
    864: 'OEM Arabic; Arabic (864)',
    865: 'OEM Nordic; Nordic (DOS)',
    866: 'OEM Russian; Cyrillic (DOS)',
    869: 'OEM Modern Greek; Greek, Modern (DOS)',
    870: 'IBM EBCDIC Multilingual/ROECE (Latin 2); IBM EBCDIC Multilingual Latin 2',
    874: 'ANSI/OEM Thai (ISO 8859-11); Thai (Windows)',
    875: 'IBM EBCDIC Greek Modern',
    932: 'ANSI/OEM Japanese; Japanese (Shift-JIS)',
    936: 'ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)',
    949: 'ANSI/OEM Korean (Unified Hangul Code)',
    950: 'ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5)',
    1026: 'IBM EBCDIC Turkish (Latin 5)',
    1047: 'IBM EBCDIC Latin 1/Open System',
    1140: 'IBM EBCDIC US-Canada (037 + Euro symbol); IBM EBCDIC (US-Canada-Euro)',
    1141: 'IBM EBCDIC Germany (20273 + Euro symbol); IBM EBCDIC (Germany-Euro)',
    1142: 'IBM EBCDIC Denmark-Norway (20277 + Euro symbol); IBM EBCDIC (Denmark-Norway-Euro)',
    1143: 'IBM EBCDIC Finland-Sweden (20278 + Euro symbol); IBM EBCDIC (Finland-Sweden-Euro)',
    1144: 'IBM EBCDIC Italy (20280 + Euro symbol); IBM EBCDIC (Italy-Euro)',
    1145: 'IBM EBCDIC Latin America-Spain (20284 + Euro symbol); IBM EBCDIC (Spain-Euro)',
    1146: 'IBM EBCDIC United Kingdom (20285 + Euro symbol); IBM EBCDIC (UK-Euro)',
    1147: 'IBM EBCDIC France (20297 + Euro symbol); IBM EBCDIC (France-Euro)',
    1148: 'IBM EBCDIC International (500 + Euro symbol); IBM EBCDIC (International-Euro)',
    1149: 'IBM EBCDIC Icelandic (20871 + Euro symbol); IBM EBCDIC (Icelandic-Euro)',
    1200: 'Unicode UTF-16, little endian byte order (BMP of ISO 10646); available only to managed applications',
    1201: 'Unicode UTF-16, big endian byte order; available only to managed applications',
    1250: 'ANSI Central European; Central European (Windows)',
    1251: 'ANSI Cyrillic; Cyrillic (Windows)',
    1252: 'ANSI Latin 1; Western European (Windows)',
    1253: 'ANSI Greek; Greek (Windows)',
    1254: 'ANSI Turkish; Turkish (Windows)',
    1255: 'ANSI Hebrew; Hebrew (Windows)',
    1256: 'ANSI Arabic; Arabic (Windows)',
    1257: 'ANSI Baltic; Baltic (Windows)',
    1258: 'ANSI/OEM Vietnamese; Vietnamese (Windows)',
    1361: 'Korean (Johab)',
    10000: 'MAC Roman; Western European (Mac)',
    10001: 'Japanese (Mac)',
    10002: 'MAC Traditional Chinese (Big5); Chinese Traditional (Mac)',
    10003: 'Korean (Mac)',
    10004: 'Arabic (Mac)',
    10005: 'Hebrew (Mac)',
    10006: 'Greek (Mac)',
    10007: 'Cyrillic (Mac)',
    10008: 'MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac)',
    10010: 'Romanian (Mac)',
    10017: 'Ukrainian (Mac)',
    10021: 'Thai (Mac)',
    10029: 'MAC Latin 2; Central European (Mac)',
    10079: 'Icelandic (Mac)',
    10081: 'Turkish (Mac)',
    10082: 'Croatian (Mac)',
    12000: 'Unicode UTF-32, little endian byte order; available only to managed applications',
    12001: 'Unicode UTF-32, big endian byte order; available only to managed applications',
    20000: 'CNS Taiwan; Chinese Traditional (CNS)',
    20001: 'TCA Taiwan',
    20002: 'Eten Taiwan; Chinese Traditional (Eten)',
    20003: 'IBM5550 Taiwan',
    20004: 'TeleText Taiwan',
    20005: 'Wang Taiwan',
    20105: 'IA5 (IRV International Alphabet No. 5, 7-bit); Western European (IA5)',
    20106: 'IA5 German (7-bit)',
    20107: 'IA5 Swedish (7-bit)',
    20108: 'IA5 Norwegian (7-bit)',
    20127: 'US-ASCII (7-bit)',
    20261: 'T.61',
    20269: 'ISO 6937 Non-Spacing Accent',
    20273: 'IBM EBCDIC Germany',
    20277: 'IBM EBCDIC Denmark-Norway',
    20278: 'IBM EBCDIC Finland-Sweden',
    20280: 'IBM EBCDIC Italy',
    20284: 'IBM EBCDIC Latin America-Spain',
    20285: 'IBM EBCDIC United Kingdom',
    20290: 'IBM EBCDIC Japanese Katakana Extended',
    20297: 'IBM EBCDIC France',
    20420: 'IBM EBCDIC Arabic',
    20423: 'IBM EBCDIC Greek',
    20424: 'IBM EBCDIC Hebrew',
    20833: 'IBM EBCDIC Korean Extended',
    20838: 'IBM EBCDIC Thai',
    20866: 'Russian (KOI8-R); Cyrillic (KOI8-R)',
    20871: 'IBM EBCDIC Icelandic',
    20880: 'IBM EBCDIC Cyrillic Russian',
    20905: 'IBM EBCDIC Turkish',
    20924: 'IBM EBCDIC Latin 1/Open System (1047 + Euro symbol)',
    20932: 'Japanese (JIS 0208-1990 and 0212-1990)',
    20936: 'Simplified Chinese (GB2312); Chinese Simplified (GB2312-80)',
    20949: 'Korean Wansung',
    21025: 'IBM EBCDIC Cyrillic Serbian-Bulgarian',
    21027: '(deprecated)',
    21866: 'Ukrainian (KOI8-U); Cyrillic (KOI8-U)',
    28591: 'ISO 8859-1 Latin 1; Western European (ISO)',
    28592: 'ISO 8859-2 Central European; Central European (ISO)',
    28593: 'ISO 8859-3 Latin 3',
    28594: 'ISO 8859-4 Baltic',
    28595: 'ISO 8859-5 Cyrillic',
    28596: 'ISO 8859-6 Arabic',
    28597: 'ISO 8859-7 Greek',
    28598: 'ISO 8859-8 Hebrew; Hebrew (ISO-Visual)',
    28599: 'ISO 8859-9 Turkish',
    28603: 'ISO 8859-13 Estonian',
    28605: 'ISO 8859-15 Latin 9',
    29001: 'Europa 3',
    38598: 'ISO 8859-8 Hebrew; Hebrew (ISO-Logical)',
    50220: 'ISO 2022 Japanese with no halfwidth Katakana; Japanese (JIS)',
    50221: 'ISO 2022 Japanese with halfwidth Katakana; Japanese (JIS-Allow 1 byte Kana)',
    50222: 'ISO 2022 Japanese JIS X 0201-1989; Japanese (JIS-Allow 1 byte Kana - SO/SI)',
    50225: 'ISO 2022 Korean',
    50227: 'ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022)',
    50229: 'ISO 2022 Traditional Chinese',
    50930: 'EBCDIC Japanese (Katakana) Extended',
    50931: 'EBCDIC US-Canada and Japanese',
    50933: 'EBCDIC Korean Extended and Korean',
    50935: 'EBCDIC Simplified Chinese Extended and Simplified Chinese',
    50936: 'EBCDIC Simplified Chinese',
    50937: 'EBCDIC US-Canada and Traditional Chinese',
    50939: 'EBCDIC Japanese (Latin) Extended and Japanese',
    51932: 'EUC Japanese',
    51936: 'EUC Simplified Chinese; Chinese Simplified (EUC)',
    51949: 'EUC Korean',
    51950: 'EUC Traditional Chinese',
    52936: 'HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ)',
    54936: 'Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030)',
    57002: 'ISCII Devanagari',
    57003: 'ISCII Bengali',
    57004: 'ISCII Tamil',
    57005: 'ISCII Telugu',
    57006: 'ISCII Assamese',
    57007: 'ISCII Oriya',
    57008: 'ISCII Kannada',
    57009: 'ISCII Malayalam',
    57010: 'ISCII Gujarati',
    57011: 'ISCII Punjabi',
    65000: 'Unicode (UTF-7)',
    65001: 'Unicode (UTF-8)'
}

def load_keys():
    with open(".cobaltstrike.beacon_keys", "rb") as fd:
        pobj = javaobj.load(fd)
        privateKey = pobj.array.value.privateKey.encoded.data

    privateKey = (
        b"-----BEGIN PRIVATE KEY-----\n"
        + base64.encodebytes(bytes(map(lambda x: x & 0xFF, privateKey)))
        + b"-----END PRIVATE KEY-----"
    )
    return privateKey

def netbiosu_decode(netbios):
    i = iter(netbios)
    b = []
    for c in i:
        b.append(((ord(c) - ord('A')) << 4) + ((ord(next(i)) - ord('A')) & 0xF))
    return bytes(b)

def decrypt_metadata(private_key_pem, encrypted_metadata):
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )

    try:
        decrypted_metadata = private_key.decrypt(
            encrypted_metadata,
            padding.PKCS1v15()
        )
        return decrypted_metadata
    except Exception as e:
        print("An error occurred during decryption:", e)
        return None

def parse_metadata(decrypted_metadata):
    fields = {}

    fields["header"] = struct.unpack(">I", decrypted_metadata[:4])[0]
    datasize = struct.unpack(">I", decrypted_metadata[4:8])[0]
    fields["datasize"] = datasize

    decrypted_metadata = decrypted_metadata[:datasize + 8]
    
    raw_key = decrypted_metadata[8:24]
    fields["raw_key"] = binascii.hexlify(raw_key).decode()
    sha256_hash = hashlib.sha256(raw_key).hexdigest()
    fields["aes_key"] = sha256_hash[:32]
    fields["hmac_key"] = sha256_hash[32:]

    charset, charset_oem = struct.unpack("<HH", decrypted_metadata[24:28])
    fields["charset"] = f"{charset:04x} {dCodepages.get(charset, '')}"
    fields["charset_oem"] = f"{charset_oem:04x} {dCodepages.get(charset_oem, '')}"

    remaining_data = decrypted_metadata[28:]
    if not re.match(b'[0-9]+\t[0-9]+\t[0-9]', remaining_data[:10]):
        bid, pid, port, flags = struct.unpack(">IIHB", remaining_data[:11])
        fields["beacon_id"] = f"{bid:04x} {bid}"
        fields["process_id"] = f"{pid:04x} {pid}"
        fields["port"] = port
        fields["flags"] = f"{flags:02x}"

        remaining_data = remaining_data[11:]
        if not re.match(rb'[0-9]+\.[0-9]+\t[0-9]+', remaining_data[:10]):
            var1, var2, var3, var4, var5, var6 = struct.unpack(">BBHIII", remaining_data[:16])
            fields["var1"] = var1
            fields["var2"] = var2
            fields["var3"] = var3
            fields["var4"] = var4
            fields["var5"] = var5
            fields["var6"] = var6

            ip_address_bytes = remaining_data[16:20]
            fields["internal_ipv4"] = ".".join(map(str, ip_address_bytes[::-1]))

    remainder = remaining_data[20:]
    for idx, field in enumerate(remainder.split(b'\t')):
        fields[f"Field_{idx}"] = field.decode(errors="replace")

    return fields

private_key_pem = load_keys()
encoded_data = input("Enter the encoded netbiosu string: ")
encrypted_metadata = netbiosu_decode(encoded_data)
decrypted_metadata = decrypt_metadata(private_key_pem, encrypted_metadata)

if decrypted_metadata:
    parsed_fields = parse_metadata(decrypted_metadata)
    
    print("Decrypted Metadata:")
    for key, value in parsed_fields.items():
        print(f"{key}: {value}")
else:
    print("Failed to decrypt metadata.")


