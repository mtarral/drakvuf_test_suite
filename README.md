# Drakvuf Test Suite

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

> Pytest-based test suite to evaluate Drakvuf  

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [References](#references)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [License](#license)

## Overview

This test suite validates Drakvuf's plugins behavior as well as their robustness.

It manages Drakvuf's execution to monitor a guest process, started by either a process injection (`createproc/shellexec`) or
by `Ansible`.

The plugins output on stdout is captured and each line is parsed as `JSON` object, then put in a queue
used by the test function to inspect plugins output data during the execution. 

## Requirements

- `Python3`
- `virtualenv`
- [`Drakvuf`](https://github.com/tklengyel/drakvuf)
- A virtual machine ready to be introspected by Drakvuf

## Setup

~~~
virtualenv -p python3 venv
source venv/bin/activate
pip install -r requirements.txt
~~~

Edit `config.yml` to specify the path to your local `Drakvuf` binary.

~~~YAML
drakvuf_bin: "/home/user/drakvuf/src/drakvuf"
~~~

## Usage

### Configuring and running a specific test 

Let's run a Drakvuf test (assuming a Windows 7 VM):

- triggering the execution of `C:\Windows\system32\reg.exe`
- via the `createproc` injection method
- injected into the `taskmgr` guest process
- activating at least the plugins [`procmon`, `crashmon`, `bsodmon`] during the execution.

The test can be found in `tests/test_injection.py`, and the CONSTANTS defined at the beginning of the file
reflects our desired configuration for this test.

Tweak them as you need.

To run the test, we launch the following command:
~~~
sudo ./venv/bin/pytest --domain win7 --profile /etc/libvmi/win7.json --inject-method createproc -k injection -x --log-level=INFO --log-file=pytest.log -v --count 200
~~~

Notes on pytest parameters:
- `-k injection`: will filter all the tests discovered by pytest to select those that matches `injection` (So, only our test will be selected)
- `-x`: will stop at first failure
- `--log-level=INFO`: pytest log level, useful to follow a long test suite, especially if you run repeated test (`--count`)
- `--log-file=pytest.log`: log pytest output in this file (follow the test progress with a `tail -f pytest.log`)
- `-v`: be more verbose in pytest log output (useful for debugging)
- `--count 200`: repeat the selected tests `200` times. Useful to validate the code's robustness on multiples Drakvuf runs.

On failure, the file `drakvuf_stderr.log` will contain Drakvuf's error output of the latest failing test.

## References

- [DRAKVUF](https://github.com/tklengyel/drakvuf)

## Maintainers

[@mtarral](https://github.com/mtarral)

## Contributing

PRs accepted.

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

GNU General Public License v3.0