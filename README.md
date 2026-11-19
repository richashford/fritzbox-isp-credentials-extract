# FRITZ!Box to UniFi Cloud Gateway settings extractor

This local command-line tool reads a password-protected FRITZ!Box `.export`
backup and displays the WAN settings needed when replacing the FRITZ!Box with a
UniFi Cloud Gateway.

It extracts only the internet PPPoE account and relevant WAN settings. The
backup password is entered through a hidden prompt, the decrypted values remain
in memory, and no decrypted backup is written to disk.

## Install

```sh
git clone https://github.com/richashford/fritzbox-isp-credentials-extract.git
cd fritzbox-isp-credentials-extract
./install.sh
```

## Use

```sh
./fritzbox-ucg /path/to/FRITZ.Box.export
```

The tool prompts for the password used when the backup was created and prints:

- PPPoE username and password
- VLAN requirement, ID and priority
- MTU and DNS configuration
- IPv6 state
- the corresponding UniFi WAN field names

To make output safe to paste into a support conversation:

```sh
./fritzbox-ucg --redact-password /path/to/FRITZ.Box.export
```

For automation or import into another local tool:

```sh
./fritzbox-ucg --json /path/to/FRITZ.Box.export
```

JSON output contains the recovered PPPoE password unless
`--redact-password` is also supplied. Avoid saving unredacted output in shell
history, tickets, logs or shared documents.

## Limitations

- The backup must have been saved with a known export password.
- The current version expects a PPPoE internet account in `ar7.cfg`.
- A UniFi Cloud Gateway requires an Ethernet handoff. A DSL-only installation
  still needs a compatible bridge modem or an ONT between the line and gateway.
- Always confirm the physical access technology and any ISP-specific settings
  before disconnecting a working router.

## Licence

This project is available under the MIT Licence. See `LICENSE`.
