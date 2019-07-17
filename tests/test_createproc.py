import logging

GUEST_TEST_BIN = 'C:\\Windows\System32\\reg.exe'
PLUGIN_LIST = ['procmon', 'crashmon', 'bsodmon']
INJECTION_CANDIDATE = "taskmgr"
INJECTION_METHOD = "createproc"


def test_createproc(ev_queue):
    event_list = [event for event in iter(ev_queue['queue'].get, None)]
    logging.info('test: finished capturing events')
    for event in event_list:
        assert(event['Plugin'] != 'crashmon')
        assert (event['Plugin'] != 'bsodmon')
    assert(ev_queue['completed'].is_set())
