import platform
import sys
import json
from typing import Optional

import click
import pyimg4

from . import __version__
from .device import Device
from .ipsw import IPSW

@click.command()
@click.version_option(message=f'Criptam {__version__}')
@click.option(
    '-b',
    '--build-id',
    'buildid',
    type=str,
    required=True,
    help='iOS/iPadOS build ID to decrypt firmware keys for.',
)
@click.option(
    '-d',
    '--device-identifier',
    'identifier',
    type=str,
    help='Device identifier to use in place of connected device (must share same SoC as connected device).',
)
@click.option(
    '--gaster',
    'use_gaster',
    is_flag=True,
    help='Use gaster to decrypt firmware keys instead of ipwndfu (requires gaster to be installed).',
)
@click.option(
    '-w',
    '--wiki',
    'wiki_print',
    is_flag=True,
    help='Print firmware keys in a format suitable for The iPhone Wiki.',
)
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Increase verbosity.',
)
def main(
    buildid: str,
    identifier: Optional[str],
    use_gaster: bool,
    wiki_print: bool,
    verbose: bool,
) -> None:
    '''A Python CLI tool for decrypting iOS/iPadOS bootchain firmware keys.'''

    if not verbose:
        sys.tracebacklimit = 0

    if platform.system() == 'Windows':
        click.echo('[ERROR] Windows systems are not supported. Exiting.')
        return

    click.echo('Attempting to connect to device')
    device = Device()

    if not device.pwned:
        click.echo('[ERROR] Device is not in Pwned DFU mode. Exiting.')
        return

    if identifier is not None:
        identifier = 'P'.join(identifier.lower().split('p'))

        if not any(i in identifier for i in ('iPhone', 'iPad', 'iPod')):
            click.echo(f'[ERROR] Invalid device identifier: {identifier}. Exiting.')
            return

    else:
        identifier = device.identifier

    click.echo(f'Getting firmware information for device: {identifier}...')
    click.echo(f'Detected SOC: {device.soc}')
    click.echo(f'Supplied identifier: {identifier}')

    firmwares = list()
    try:
        with open('fw.json', 'r') as f:
            api = json.load(f)
            print(f"Loaded JSON from fw.json")
    except json.JSONDecodeError as e:
        click.echo(f"[ERROR] Failed to decode JSON: {e}")
        return
    except FileNotFoundError as e:
        click.echo(f"[ERROR] File not found: {e}")
        return

    firms = api.get('firmwares', [])

    for firm in firms:
        if any(firm['buildid'] == f['buildid'] for f in firmwares):
            continue

        firmwares.append(firm)

    firmwares = sorted(firmwares, key=lambda x: x['buildid'], reverse=True)

    try:
        firmware = next(
            firm
            for firm in firmwares
            if firm['buildid'].casefold() == buildid.casefold()
        )
    except StopIteration:
        click.echo(
            f'Build {buildid} does not exist for device: {device.identifier}. Exiting.'
        )
        return

    buildid = firmware['buildid']

    try:
        ipsw = IPSW(device, firmware['url'])
        manifest = ipsw.read_manifest()
    except:
        click.echo(
            f'Failed to download build manifest for firmware: {buildid}, device: {device.identifier}. Exiting.'
        )
        return

    identity = next(id_ for id_ in manifest.identities if id_.chip_id == device.chip_id)

    click.echo(f'Decrypting keys for firmware: {buildid}, device: {identifier}...')

    keybags = {
        'iBSS': None,
        'iBEC': None,
        'LLB': None,
        'iBoot': None,
    }
    for component in keybags.keys():
        image = pyimg4.IM4P(
            ipsw.read_file(next(i.path for i in identity.images if i.name == component))
        )
        if image is None:
            click.echo(
                f'Failed to download {component} for firmware: {buildid}, device: {device.identifier}. Exiting.'
            )
            return

        keybag = next(
            kbag
            for kbag in image.payload.keybags
            if kbag.type == pyimg4.KeybagType.PRODUCTION
        )

        keybags[component] = device.decrypt_keybag(
            keybag, _backend='ipwndfu' if not use_gaster else 'gaster'
        )

    keys_title = 'Firmware keys'

    if identity.chip_id in (0x8000, 0x8003):
        keys_title += f' ({identity.board_config})'

    if wiki_print:
        keys_title += ' (The iPhone Wiki format)'

    click.echo(f'{keys_title}:')
    if wiki_print:
        for component in ('iBEC', 'iBoot', 'iBSS', 'LLB'):
            iv_str = f' | {component}IV'
            click.echo(
                f"{iv_str + (' ' * (24 - len(iv_str)))} = {keybags[component].iv.hex()}"
            )

            key_str = f' | {component}Key'
            click.echo(
                f"{key_str + (' ' * (24 - len(key_str)))} = {keybags[component].key.hex()}"
            )

            if component != 'LLB':
                click.echo()
    else:
        for component, keybag in keybags.items():
            click.echo(f'{component} IV: {keybags[component].iv.hex()}')
            click.echo(f'{component} Key: {keybags[component].key.hex()}')

            if component != 'iBoot':
                click.echo()

if __name__ == '__main__':
    main()
