import logging

# GUEST_TEST_BIN = 'C:\\Users\\Jonas\\Desktop\\stress_test.ps1'
GUEST_TEST_BIN = 'C:\\Windows\System32\\reg.exe'
PLUGIN_LIST = ['procmon', 'crashmon', 'bsodmon']
INJECTION_CANDIDATE = 'taskmgr'
INJECTION_METHOD = 'shellexec'


def test_shellexec(ev_queue):
    for event in iter(ev_queue['queue'].get, None):
        assert(event['Plugin'] != 'crashmon')
        assert (event['Plugin'] != 'bsodmon')
    assert(ev_queue['completed'].is_set())
