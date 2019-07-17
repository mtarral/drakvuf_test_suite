PLUGIN_LIST = ['procmon', 'crashmon', 'bsodmon']

def test_injection(ev_queue):
    for event in iter(ev_queue['queue'].get, None):
        assert(event['Plugin'] != 'crashmon')
        assert (event['Plugin'] != 'bsodmon')
    assert(ev_queue['completed'].is_set())
