#!/usr/bin/env python3
"""Stage one scoped endpoint active-response setting; preserve all other text."""
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


def disable(config):
    ET.fromstring('<root>' + config + '</root>')
    sections = list(re.finditer(r'<active-response\s*>.*?</active-response\s*>', config, re.S))
    if len(sections) > 1:
        raise ValueError('Multiple endpoint active-response sections require manual review')
    if sections:
        section = sections[0]
        text = section.group()
        values = re.findall(r'<disabled>\s*(.*?)\s*</disabled>', text, re.S)
        if len(values) > 1 or (values and values[0] not in ('yes', 'no')):
            raise ValueError('Unrecognized endpoint active-response setting')
        if values:
            replacement = re.sub(r'(<disabled>\s*)(yes|no)(\s*</disabled>)', r'\g<1>yes\3', text, count=1)
        else:
            replacement = text.replace('</active-response', '<disabled>yes</disabled></active-response', 1)
        updated = config[:section.start()] + replacement + config[section.end():]
    else:
        if '</ossec_config>' not in config:
            raise ValueError('No endpoint ossec_config block')
        updated = config.replace('</ossec_config>', '<active-response><disabled>yes</disabled></active-response>\n</ossec_config>', 1)
    values = ET.fromstring('<root>' + updated + '</root>').findall('./ossec_config/active-response/disabled')
    if len(values) != 1 or (values[0].text or '').strip() != 'yes':
        raise ValueError('Scoped response disablement did not produce exactly one enabled safeguard')
    return updated


if __name__ == '__main__':
    Path(sys.argv[2]).write_text(disable(Path(sys.argv[1]).read_text()))
