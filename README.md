# Simple Command Line Multicast Testing Tool

**Download for Windows and Linux:** [https://github.com/enclave-networks/multicast-test/releases/tag/multicast-test-v1.0.1.0](https://github.com/enclave-networks/multicast-test/releases/tag/multicast-test-v1.0.1.0)

Testing multicast traffic can be challenging and tends to involve running an application on two systems, phsical or virtual connected to  the network.

Usually we might reach for iPerf and/or multicast video streaming in VLC. Both are useful but, iPerf3 has removed support for multicast traffic, and sometimes its not as obvious as it could be whether the tools are doing what we think they are. iPerf can be complicated, and VLC multicast streaming can be buggy.

![select an interface](https://github.com/enclave-networks/multicast-test/raw/master/select.png)

This is a simpler command-line tool that runs on both Linux and Windows which you can use to validate multicast connectivity. Run the tool on two or more different machines. Choose the relevant interface on both systems and then select action option 1 to transmit data, and action option 2 to recieve.

> Note. don't try using interface 0 (any) to send, it won't work. Pick the speicifc interface you want to test instead.

On the sending host you'll see output like this (option 1):

![sending data](https://github.com/enclave-networks/multicast-test/raw/master/sending.png)

![receiving data](https://github.com/enclave-networks/multicast-test/raw/master/receiving.png)

See also the [Singlewire Multicast Testing Tool](https://support.singlewire.com/s/software-downloads/a17C0000008Dg7AIAS/ictestermulticastzip) discussed [here](https://salmannaqvi.com/2016/11/14/simple-multicast-testing-tool-for-windows/) by Salman Naqvi – 2 x CCIE. The Singlewire tool is perfectly adequate if you have a single network interface, but if you're working on systems with multiple network interfaces, this version should be quite useful.

## Python version

`multicast_test.py` is a Python port of this tool with the same workflow and defaults. It uses only the Python standard library — no third-party packages, no `pip install`, no admin rights. Any Python 3.x on Windows or Linux will run it.

Interactive mode (same prompts as the .NET tool):

```
python multicast_test.py
```

Command-line mode, useful for scripting:

```
python multicast_test.py -m recv                          # listen on the default group/port
python multicast_test.py -m send -c 10                    # send 10 messages, then exit
python multicast_test.py -m send -i 192.168.1.10          # bind to a specific interface
python multicast_test.py -m recv -g 239.0.1.2 -p 20480
```

| Flag | Description | Default |
|------|-------------|---------|
| `-m, --mode` | `send` or `recv` (omit to use interactive prompts) | interactive |
| `-i, --interface` | Local IP to bind | `0.0.0.0` |
| `-g, --group` | Multicast group address | `239.0.1.2` |
| `-p, --port` | UDP port | `20480` |
| `-c, --count` | Sender only: stop after N messages | send forever |

The same caveats apply as for the .NET tool: don't use interface `0.0.0.0` to send — bind to a specific interface instead. On Windows, the firewall will block the receiver on first run until the app is allowed through.
