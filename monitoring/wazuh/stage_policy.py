#!/usr/bin/env python3
"""Build an analysisd validation view without writing the live configuration."""
import argparse
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET


def stage(root, workspace):
    root, workspace = Path(root), Path(workspace)
    config = (root / 'etc/ossec.conf').read_text()
    for tag, directory in (('rule_dir', 'rules'), ('decoder_dir', 'decoders')):
        pattern = rf'(<{tag}>\s*)etc/{directory}(\s*</{tag}>)'
        if len(re.findall(pattern, config)) != 1:
            raise ValueError('Expected one standard custom policy directory; review nonstandard manager configuration')
        staged = workspace / ('staged-' + directory)
        shutil.copytree(root / 'etc' / directory, staged, dirs_exist_ok=True)
        source = workspace / 'source' / directory / ('homelab_' + directory + '.xml')
        ET.fromstring(source.read_text())
        shutil.copyfile(source, staged / source.name)
        # analysisd enumerates relative paths before chroot and opens them after
        # chroot(/var/ossec). An in-root relative path works in both phases.
        validation_path = str(staged.relative_to(root))
        config = re.sub(pattern, lambda m: m[1] + validation_path + m[2], config)
    (workspace / 'ossec-validation.conf').write_text(config)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('root')
    parser.add_argument('workspace')
    args = parser.parse_args()
    stage(args.root, args.workspace)
