import logging
import pytest
from collections import Counter
from pathlib import PureWindowsPath


GUEST_TEST_BIN = 'C:\\Users\\vagrant\\Desktop\\stress_test.ps1'


def test_powershell(ev_queue):
    # check if we have 100 createprocess and terminate process
    stats = Counter()
    for event in iter(ev_queue.get, None):
        if event['Plugin'] == 'procmon':
            current = PureWindowsPath(event['ProcessName']).name
            if event['Method'] == 'NtCreateUserProcess':
                created = PureWindowsPath(event['ImagePathName']).name
                print('{} creating {}'.format(current, created))
                stats['create'] += 1
            if event['Method'] == 'NtTerminateProcess':
                destructed = int(event['ExitPid'])
                print('{} terminated {}'.format(current, destructed))
                stats['terminate'] += 1
    assert(stats['create'] >= 100)
    assert(stats['terminate'] >= 100)
