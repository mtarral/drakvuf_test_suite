import logging
import re
import time
import json
import yaml
import pytest
import signal
import threading
import subprocess
from queue import Queue
from pathlib import PureWindowsPath, Path
from collections import Counter
from tempfile import TemporaryFile

# read config
config = None
with open('config.yml') as config_f:
    config = yaml.load(config_f.read())


DRAKVUF_BIN = config['drakvuf_bin']
DRAKVUF_PLUGIN_LIST = [
    'bsodmon',
    'clipboardmon',
    'cpuidmon',
    'crashmon',
    'debugmon',
    'delaymon',
    'dkommon',
    'envmon',
    'exmon',
    'filedelete',
    'filetracer',
    'librarymon',
    'objmon',
    'procmon',
    'regmon',
    'socketmon',
    'ssdtmon',
    'windowmon'
]
DEFAULT_ENABLE_INJECTION = True
DEFAULT_GUEST_TEST_BIN = 'C:\\Windows\\System32\\cmd.exe'
DEFAULT_TIMEOUT = 60
DEFAULT_INJECTION_CANDIDATE = 'taskmgr'
# createproc, shellexec, ansible
DEFAULT_INJECTION_METHOD = 'shellexec'


# add command line options to specify domain and profile
def pytest_addoption(parser):
    parser.addoption(
        '--domain', action='store', help='Specify domain name'
    )
    parser.addoption(
        '--profile', action='store', help='Specify kernel rekall profile'
    )


# make test status available in fixture teardown code
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    # set an attribute for each phase of a call
    "setup" "call" "teardown"
    setattr(item, "rep_" + rep.when, rep)


# functions to find DOM -> IP_addr
def get_mac(dom_name):
    # run xl network-list and parse the output
    cmdline = ['xl', 'network-list', dom_name]
    output = subprocess.check_output(cmdline)

    # take first entry, VM should have only one network card
    entry = output.decode().splitlines()[1]
    m = re.match(r'.*\s+(?P<mac>([0-9a-fA-f]{2}:?){6})\s+.*', entry)
    if not m:
        raise RuntimeError('Unable to find mac address for domain %s', dom_name)
    return m.group('mac')


def get_ip(mac):
    cmdline = ['ip', 'neigh', 'show']
    output = subprocess.check_output(cmdline)
    for line in output.decode().splitlines():
        m = re.match(r'(?P<ip>\S+).*(?P<mac>([0-9a-fA-f]{2}:?){6})\s.*', line)
        if not m:
            continue
        if m.group('mac') == mac:
            return m.group('ip')
    raise RuntimeError('Cannot find ip address for mac %s', mac)


def injection_candidate(domain, name):
    proc = subprocess.run(['vmi-process-list', domain], check=True, stdout=subprocess.PIPE)
    matches = re.findall('\[\s*(?P<pid>\d+)]\s(?P<name>\S+)\s.*', proc.stdout.decode(), re.MULTILINE)
    found = [proc for proc in matches if re.match(name, proc[1].lower())]
    if not found:
        logging.error(proc.stdout)
        raise RuntimeError('Cannot locate %s in process list' % name)
    # return first match
    return found[0]


@pytest.fixture(scope='function')
def drak_proc(request):
    domain_name = request.config.getoption('--domain')
    profile_path = request.config.getoption('--profile')
    profile = ['-r', profile_path]
    domain = ['-d', domain_name]
    # plugins ?
    plugin_list = getattr(request.module, "PLUGIN_LIST", [])
    plugins = []
    for plugin in plugin_list:
        plugins.append('-a')
        plugins.append(plugin)
    output_fmt = ['-o', 'json']
    verbose = ['-v']
    # build cmdline
    cmdline = [DRAKVUF_BIN]
    cmdline.extend(profile)
    cmdline.extend(domain)
    cmdline.extend(plugins)
    cmdline.extend(output_fmt)

    injection_enabled = getattr(request.module, "ENABLE_INJECTION", DEFAULT_ENABLE_INJECTION)
    # get injection method
    injection_method = getattr(request.module, "INJECTION_METHOD", DEFAULT_INJECTION_METHOD)
    if injection_enabled and injection_method != 'ansible':
        domain = request.config.getoption('--domain')
        candidate_name = getattr(request.module, "INJECTION_CANDIDATE", DEFAULT_INJECTION_CANDIDATE)
        candidate = injection_candidate(domain, candidate_name)
        candidate_pid = candidate[0]
        injection_cmd = ['-i', str(candidate_pid), '-m', injection_method]
        global_search = ['-g']
        guest_test_bin = getattr(request.module, "GUEST_TEST_BIN", DEFAULT_GUEST_TEST_BIN)
        remote_bin = ['-e', guest_test_bin]
        cmdline.extend(remote_bin)
        cmdline.extend(injection_cmd)
        cmdline.extend(global_search)

    cmdline.extend(verbose)
    # run drakvuf
    logging.info('==== {} ====\n'.format(request.node.name).encode())
    logging.info(cmdline)
    # stderr is very verbose so use a TemporaryFile (hopefully in memory)
    with TemporaryFile() as tmp_stderr:
        tmp_stderr.write('==== {} ====\n'.format(request.node.name).encode())
        # need to flush otherwise the previous message is written at the end
        # and not at the beginning
        tmp_stderr.flush()
        proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=tmp_stderr)
        yield proc
        # only append to drakvuf_stderr.log if test failed
        if request.node.rep_setup.passed and request.node.rep_call.failed:
            with open('drakvuf_stderr.log', 'ab') as log_stderr:
                tmp_stderr.seek(0)
                log_stderr.write(tmp_stderr.read())
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
    proc.wait(10)


def follow_process(injection_enabled, guest_binary_path, drak_proc, queue, completed_process):
    stats = Counter()
    guest_binary_name = PureWindowsPath(guest_binary_path).name
    target_pid = None
    while not completed_process.is_set():
        line = drak_proc.stdout.readline()
        if len(line) == 0:
            # EOF, process is dead
            break
        try:
            event = json.loads(line.decode('utf-8'))
        except json.decoder.JSONDecodeError:
            logging.error('Invalid JSON: %s', line)
            stats['json_error'] += 1
        else:
            # push event in queue
            queue.put(event)
            if injection_enabled:
                if event['Plugin'] == 'procmon':
                    current = PureWindowsPath(event['ProcessName'])
                    if event['Method'] == 'NtCreateUserProcess':
                        created = PureWindowsPath(event['ImagePathName'])
                        logging.info('process %s started: %s (%d)', current.name, created.name, int(event['NewPid']))
                        # Ansible injection method: match binary name
                        # creatproc/shellexec: match conhost.exe (must start a command line application)
                        if created.name == guest_binary_name\
                                or created.name == "conhost.exe":
                            # use this event as target start
                            target_pid = int(event['NewPid'])
                            logging.info('target started: %s (%d)', created.name, target_pid)
                    if event['Method'] == 'NtTerminateProcess':
                        destructed = int(event['ExitPid'])
                        logging.info('process %s killed %d', current.name, destructed)
                        if destructed == target_pid:
                            completed_process.set()
                            # push None in queue to indicate end of events
                            # if there was an event to catch for a test before, it has been missed
                            queue.put(None)
                            logging.info('target execution completed')
        finally:
            stats['processed'] += 1
    logging.info('Processed %d events (%d) errors', stats['processed'], stats['json_error'])


def test_timeout(queue, completed_process):
    if not completed_process.wait(DEFAULT_TIMEOUT):
        logging.info('Test Timeout !')
        # timeout !
        # stop test
        queue.put(None)


# thread to watch drakvuf if process injection fails and it dies early
def watch_dead(drak_proc, queue):
    while True:
        try:
            ret = drak_proc.wait(1)
        except subprocess.TimeoutExpired:
            pass
        else:
            # drakvuf died, send stop event
            logging.info('drakvuf process terminated')
            queue.put(None)
            break


def ansible_run(domain_name, guest_test_bin, queue, completed_process):
    logging.debug('waiting for drakvuf to start monitoring...')
    time.sleep(2)
    mac = get_mac(domain_name)
    logging.debug('mac address: %s', mac)
    ip_addr = get_ip(mac)
    logging.debug('ip address: %s', ip_addr)
    inventory = ['--inventory', '{},'.format(ip_addr)]
    connection = ['--connection', 'winrm']
    username = ['--extra-vars', 'ansible_user=vagrant']
    password = ['--extra-vars', 'ansible_password=vagrant']
    scheme = ['--extra-vars', 'ansible_winrm_scheme=http']
    port = ['--extra-vars', 'ansible_port=5985']
    run_command = ['--module-name', 'win_command', '--args', guest_test_bin]
    # run ansible from the venv to have winrm installed
    ansible_bin = str(Path(__file__).parent / 'venv' / 'bin' / 'ansible')
    cmdline = [ansible_bin, '*']
    cmdline.extend(inventory)
    cmdline.extend(connection)
    cmdline.extend(username)
    cmdline.extend(password)
    cmdline.extend(scheme)
    cmdline.extend(port)
    cmdline.extend(run_command)
    logging.debug(cmdline)
    proc = subprocess.run(cmdline, stdout=subprocess.PIPE)
    if re.search(r'REG\s+/\?', proc.stdout.decode()):
        completed_process.set()
        queue.put(None)


@pytest.fixture(scope='function')
def ev_queue(request, drak_proc):
    # create event queue
    queue = Queue()
    completed_process = threading.Event()
    injection_enabled = getattr(request.module, "ENABLE_INJECTION", DEFAULT_ENABLE_INJECTION)
    injection_method = getattr(request.module, "INJECTION_METHOD", DEFAULT_INJECTION_METHOD)
    guest_test_bin = getattr(request.module, "GUEST_TEST_BIN", DEFAULT_GUEST_TEST_BIN)
    if injection_method == 'ansible':
        domain_name = request.config.getoption('--domain')
        ansible_thread = threading.Thread(target=ansible_run, args=(domain_name, guest_test_bin, queue, completed_process))
        ansible_thread.start()
    # follow process execution
    # stop drakvuf
    dead_thread = threading.Thread(target=watch_dead, args=(drak_proc, queue))
    dead_thread.start()
    event_thread = threading.Thread(target=follow_process, args=(injection_enabled, guest_test_bin, drak_proc, queue, completed_process))
    event_thread.start()
    timeout_thread = threading.Thread(target=test_timeout, args=(queue, completed_process))
    timeout_thread.start()
    run_info = {
        'proc': drak_proc,
        'queue': queue,
        'completed': completed_process,
    }
    yield run_info
    logging.info('test finished')
    # test has completed
    # terminate follow_process thread loop (if injection was disabled, or
    # we missed an event to intercept targeted process creation or termination)
    completed_process.set()
    # stop drakvuf
    logging.debug('stopping drakvuf')
    drak_proc.send_signal(signal.SIGINT)
    drak_proc.wait(10)
    # make sure our threads are completed
    event_thread.join()
    timeout_thread.join()
    dead_thread.join()
    if injection_method == 'ansible':
        ansible_thread.join()
