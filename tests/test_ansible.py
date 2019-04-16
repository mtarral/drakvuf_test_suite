import logging

GUEST_TEST_BIN = 'C:\\Windows\System32\\cmd.exe'
PLUGIN_LIST = ['procmon', 'crashmon', 'bsodmon']
INJECTION_METHOD = "ansible"


def test_ansible(ev_queue):
    event_list = [event for event in iter(ev_queue['queue'].get, None)]
    for event in event_list:
        assert(event['Plugin'] != 'crashmon')
        assert (event['Plugin'] != 'bsodmon')
    assert(ev_queue['completed'].is_set())
