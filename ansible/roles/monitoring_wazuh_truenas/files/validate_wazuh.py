"""Refuse duplicate/unowned localfile declarations before a marked XML edit."""
import re
import sys
import xml.etree.ElementTree as ET

BEGIN = '<!-- BEGIN homelab-truenas-localfile -->'
END = '<!-- END homelab-truenas-localfile -->'
LOCATION = '/var/log/homelab-truenas/events.log'


def validate(text):
    # Wazuh permits multiple top-level ossec_config sections.
    root = ET.fromstring('<root>' + text + '</root>')
    if not list(root) or any(c.tag != 'ossec_config' for c in root):
        raise ValueError('Expected only ossec_config roots')
    if not re.search(r'^</ossec_config>\s*$', text, re.M):
        raise ValueError('No unambiguous closing config line for marked insertion')
    owned = ''
    if BEGIN in text or END in text:
        if text.count(BEGIN) != 1 or text.count(END) != 1:
            raise ValueError('Ambiguous owned marker')
        start, finish = text.index(BEGIN), text.index(END)
        if finish < start:
            raise ValueError('Reversed owned markers')
        owned = text[start:finish + len(END)]
        owned_root = ET.fromstring('<ossec_config>' + owned + '</ossec_config>')
        if (len(owned_root) != 1 or owned_root[0].tag != 'localfile'
                or owned_root[0].findtext('location') != LOCATION
                or owned_root[0].findtext('log_format') != 'syslog'):
            raise ValueError('Owned block contains unexpected policy')
    other = text.replace(owned, '', 1) if owned else text
    if any(n.text and n.text.strip() == LOCATION for n in
           ET.fromstring('<root>' + other + '</root>').iter('location')):
        raise ValueError('Unowned localfile already collects target log; review ownership')


if __name__ == '__main__':
    with open(sys.argv[1], encoding='utf-8') as handle:
        validate(handle.read())
