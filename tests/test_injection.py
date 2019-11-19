# the PLUGIN_LIST constant declares the plugins required for the test
# here our test_injection will only need crashmon and bsodmon.
# however, we also include procmon and filetracer, because this is required
# for every test to follow the guest process execution and determine when the
# execution has been completed.
PLUGIN_LIST = ['procmon', 'filetracer', 'crashmon', 'bsodmon']


def test_injection(ev_queue):
    for event in iter(ev_queue['queue'].get, None):
        assert(event['Plugin'] != 'crashmon')
        assert (event['Plugin'] != 'bsodmon')
    assert(ev_queue['completed'].is_set())
