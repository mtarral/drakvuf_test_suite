import logging
import subprocess
import re

INJECTION_CANDIDATE = "taskmgr"
VM = 'win7'


def test_processlist():
    name = INJECTION_CANDIDATE
    proc = subprocess.run(['vmi-process-list', VM], check=True, stdout=subprocess.PIPE)
    matches = re.findall('\[\s*(?P<pid>\d+)]\s(?P<name>\S+)\s.*', proc.stdout.decode(), re.MULTILINE)
    found = [proc for proc in matches if re.match(name, proc[1].lower())]
    if not found:
        logging.debug(proc.stdout.splitlines())
    assert(found)
