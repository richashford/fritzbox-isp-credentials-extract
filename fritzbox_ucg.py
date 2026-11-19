#!/usr/bin/env python3
"""Extract replacement UniFi gateway WAN settings from a FRITZ!Box export.

The export password is requested with getpass and is never echoed. Only the
internet PPPoE credentials and relevant WAN parameters are decrypted. No
decrypted backup is written to disk.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - exercised by installation failures
    AES = None


class FritzboxError(Exception):
    """A safe, user-facing error while reading or decrypting a backup."""


FRITZ_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
FRITZ_BASE32_LOOKUP = {char: index for index, char in enumerate(FRITZ_BASE32_ALPHABET)}


@dataclass
class UcgSettings:
    source_file: str
    fritzbox_model: str
    fritzos_version: str
    provider: str
    ipv4_connection: str
    pppoe_username: str
    pppoe_password: str
    vlan_enabled: bool
    vlan_id: int | None
    vlan_priority: int | None
    mtu: str
    dns: str
    ipv6: str


def fritz_base32_decode(value: str) -> bytes:
    output = bytearray()
    buffer = 0
    bit_count = 0
    for char in value:
        if char not in FRITZ_BASE32_LOOKUP:
            raise FritzboxError("The backup contains an invalid encrypted value.")
        buffer = (buffer << 5) | FRITZ_BASE32_LOOKUP[char]
        bit_count += 5
        if bit_count >= 8:
            bit_count -= 8
            output.append((buffer >> bit_count) & 0xFF)
    return bytes(output)


def decode_secret(secret: str, key: bytes, *, string_value: bool) -> bytes:
    if AES is None:
        raise FritzboxError(
            "The encryption dependency is missing. Run ./install.sh, then try again."
        )
    if not secret.startswith("$$$$"):
        return secret.encode("utf-8")

    raw = fritz_base32_decode(secret[4:])
    excess = len(raw) % 16
    if excess > 4:
        raise FritzboxError("The backup contains malformed encrypted data.")
    if excess:
        raw = raw[:-excess]
    if len(raw) < 32:
        raise FritzboxError("The backup contains a truncated encrypted value.")

    iv, ciphertext = raw[:16], raw[16:]
    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    checksum, payload = plaintext[:4], plaintext[4:]
    if hashlib.md5(payload).digest()[:4] != checksum:
        raise FritzboxError("The backup password is incorrect, or the backup is damaged.")

    length = int.from_bytes(payload[:4], "big")
    data = payload[4 : 4 + length]
    if string_value:
        if not data.endswith(b"\0"):
            raise FritzboxError("The backup contains an invalid encrypted string.")
        data = data[:-1]
    return data


def export_key(encrypted_key: str, password: str) -> bytes:
    bootstrap = hashlib.md5(password.encode("utf-8")).digest().ljust(32, b"\0")
    key = decode_secret(encrypted_key, bootstrap, string_value=False)
    if len(key) != 32:
        raise FritzboxError("The backup encryption key is invalid.")
    # FRITZ!OS stores a 128-bit value for use as an AES-256 key padded with zeros.
    return key[:16] + (b"\0" * 16)


def cfg_section(export_text: str, name: str) -> str:
    pattern = re.compile(
        rf"^\*\*\*\* CFGFILE:{re.escape(name)}\s*$\n(.*?)^\*\*\*\* END OF FILE \*\*\*\*\s*$",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(export_text)
    if not match:
        raise FritzboxError(f"The backup does not contain {name}.")
    return match.group(1)


def enclosing_block(text: str, marker: str, block_name: str | None = None) -> str:
    marker_pos = text.find(marker)
    if marker_pos < 0:
        raise FritzboxError(f"Could not locate {marker!r} in the internet configuration.")

    search_end = marker_pos
    if block_name:
        # The marker may be the block declaration itself (for example
        # ``local {``), so include the marker and its opening brace in the
        # backwards search window.
        search_window_end = min(len(text), marker_pos + len(marker) + 2)
        candidates = list(
            re.finditer(
                rf"\b{re.escape(block_name)}\s*\{{",
                text[:search_window_end],
            )
        )
        if not candidates:
            raise FritzboxError(f"Could not locate the {block_name} configuration block.")
        start = candidates[-1].start()
        open_brace = text.find("{", start, search_window_end)
    else:
        open_brace = text.rfind("{", 0, search_end)
        start = open_brace

    if open_brace < 0:
        raise FritzboxError("The internet configuration is malformed.")

    depth = 0
    in_string = False
    escaped = False
    for index in range(open_brace, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise FritzboxError("The internet configuration contains an unterminated block.")


def value(block: str, key: str, *, required: bool = True) -> str | None:
    match = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.*?);\s*$", block, re.MULTILINE)
    if not match:
        if required:
            raise FritzboxError(f"The internet configuration has no {key} value.")
        return None
    result = match.group(1).strip()
    if len(result) >= 2 and result[0] == result[-1] == '"':
        result = result[1:-1]
    return result


def decrypted_text(raw: str, key: bytes) -> str:
    if not raw.startswith("$$$$"):
        return raw
    return decode_secret(raw, key, string_value=True).decode("utf-8", errors="strict")


def integer_or_none(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def parse_backup(path: Path, password: str) -> UcgSettings:
    try:
        export_text = path.read_text(encoding="utf-8", errors="surrogateescape")
    except OSError as exc:
        raise FritzboxError(f"Could not read {path}: {exc.strerror or exc}") from exc

    header = re.search(r"^\*\*\*\* (.+?) CONFIGURATION EXPORT\s*$", export_text, re.MULTILINE)
    encrypted_key_match = re.search(r"^Password=(\$\$\$\$[A-Z1-6]+)\s*$", export_text, re.MULTILINE)
    firmware = re.search(r"^FirmwareVersion=(.+?)\s*$", export_text, re.MULTILINE)
    if not header or not encrypted_key_match:
        raise FritzboxError("This does not appear to be a password-protected FRITZ!Box export.")

    key = export_key(encrypted_key_match.group(1), password)
    ar7 = cfg_section(export_text, "ar7.cfg")

    target_marker = 'type = pppcfg_target_internet;\n                name = "internet";'
    if target_marker not in ar7:
        # Whitespace varies between FRITZ!OS releases.
        match = re.search(r'type\s*=\s*pppcfg_target_internet;\s*name\s*=\s*"internet";', ar7)
        if not match:
            raise FritzboxError("No internet PPPoE account was found in this backup.")
        target_marker = match.group(0)
    target = enclosing_block(ar7, target_marker, "targets")
    local_marker = re.search(r"\blocal\s*\{", target)
    if not local_marker:
        raise FritzboxError("The PPPoE account has no local credentials block.")
    local = enclosing_block(target, local_marker.group(0), "local")

    username = decrypted_text(value(local, "username") or "", key)
    pppoe_password = decrypted_text(value(local, "passwd") or "", key)
    if not username or not pppoe_password:
        raise FritzboxError("The internet PPPoE username or password is empty.")

    internet_match = re.search(r'\bname\s*=\s*"internet";.*?\bdsl_encap\s*=\s*dslencap_pppoe;', ar7, re.DOTALL)
    if not internet_match:
        raise FritzboxError("No PPPoE WAN connection definition was found.")
    internet = enclosing_block(ar7, internet_match.group(0), "dslifaces")

    vlan_block_match = re.search(r"\bvlancfg\s*\{", internet)
    vlan_block = (
        enclosing_block(internet, vlan_block_match.group(0), "vlancfg")
        if vlan_block_match
        else ""
    )
    vlan_encap = value(vlan_block, "vlanencap", required=False)
    vlan_id = integer_or_none(value(vlan_block, "vlanid", required=False))
    vlan_priority = integer_or_none(value(vlan_block, "vlanprio", required=False))
    vlan_enabled = bool(vlan_encap and vlan_encap != "vlanencap_none" and vlan_id not in (None, 0))

    mtu_raw = value(internet, "mtu", required=False)
    mtu = "Auto" if mtu_raw in (None, "0") else mtu_raw
    stack_mode = value(internet, "stackmode", required=False) or ""
    if stack_mode == "stackmode_ipv4only":
        ipv6 = "Disabled"
    elif "ipv6" in stack_mode:
        ipv6 = "Enabled (confirm delegated-prefix settings with the ISP)"
    else:
        ipv6 = "Use ISP/default setting"

    dns1 = value(internet, "dns1", required=False)
    dns2 = value(internet, "dns2", required=False)
    dns = "Auto"
    if dns1 and dns1 != "0.0.0.0":
        dns = dns1 if not dns2 or dns2 == "0.0.0.0" else f"{dns1}, {dns2}"

    provider_match = re.search(r'^\s*active_provider\s*=\s*"([^"]*)";', ar7, re.MULTILINE)
    provider = provider_match.group(1) if provider_match else "Unknown"

    return UcgSettings(
        source_file=str(path),
        fritzbox_model=header.group(1),
        fritzos_version=firmware.group(1) if firmware else "Unknown",
        provider=provider,
        ipv4_connection="PPPoE",
        pppoe_username=username,
        pppoe_password=pppoe_password,
        vlan_enabled=vlan_enabled,
        vlan_id=vlan_id if vlan_enabled else None,
        vlan_priority=vlan_priority if vlan_enabled else None,
        mtu=mtu,
        dns=dns,
        ipv6=ipv6,
    )


def print_human(settings: UcgSettings, *, redact_password: bool) -> None:
    password = "[redacted]" if redact_password else settings.pppoe_password
    vlan = "Disabled"
    if settings.vlan_enabled:
        vlan = str(settings.vlan_id)
        if settings.vlan_priority is not None:
            vlan += f" (priority {settings.vlan_priority})"

    print("\nFRITZ!Box backup")
    print(f"  Model:              {settings.fritzbox_model}")
    print(f"  FRITZ!OS:           {settings.fritzos_version}")
    print(f"  Provider:           {settings.provider}")
    print("\nUniFi Cloud Gateway — Settings > Internet > Primary (WAN1)")
    print(f"  IPv4 Connection:    {settings.ipv4_connection}")
    print(f"  Username:           {settings.pppoe_username}")
    print(f"  Password:           {password}")
    print(f"  VLAN ID:            {vlan}")
    print(f"  MTU:                {settings.mtu}")
    print(f"  DNS Server:         {settings.dns}")
    print(f"  IPv6:               {settings.ipv6}")
    print("  MAC Address Clone:  Disabled")
    print("\nNo decrypted backup was written to disk.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover the WAN settings needed to replace a FRITZ!Box with a UniFi Cloud Gateway."
    )
    parser.add_argument("backup", type=Path, help="FRITZ!Box .export backup file")
    parser.add_argument(
        "--redact-password",
        action="store_true",
        help="hide the recovered PPPoE password in the output",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="output machine-readable JSON (includes the password unless --redact-password is used)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    password = getpass.getpass("FRITZ!Box backup password: ")
    try:
        settings = parse_backup(args.backup.expanduser().resolve(), password)
    except FritzboxError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        password = ""  # Do not retain the user's password longer than necessary.

    if args.json:
        result = asdict(settings)
        if args.redact_password:
            result["pppoe_password"] = "[redacted]"
        print(json.dumps(result, indent=2))
    else:
        print_human(settings, redact_password=args.redact_password)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
