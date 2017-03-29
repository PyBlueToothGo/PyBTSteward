# PyBTSteward
A tool to report telemetry and more from bluetooth devices.
Currently it reports telemetry data to statsd. But there are many future plans in store.

This tool started life as a python script for scanning and advertising
urls over [Eddystone-URL](https://github.com/nirmankarta/PyBeacon).

I needed a tool to be able to use a Raspberry Pi 3 pull telemetry data from bluetooth devices, and this
seemed like a phenomenal starting point.

I subsequently found Patrick Van Oosterwijck's [py-decode-beacon](https://github.com/xorbit/py-decode-beacon)
which also did a lot of what I wanted, but not all.

I'd like to thank these authors, as well as the authors and contributors to the
myriad opensource projects I'm standing on the shoulders of to make this tool.
It is not my intent to take credit for any of their work. Merely to adapt and
continue to share.

I've also recompiled the Bluez packages for Raspbian Jessie to utilize the
latest available version. I've shared them on artifactory.

[You can find that repository here](https://bintray.com/wolfspyre/rpiBluez/bluetooth)

## Requirements

* Python 3.x (Scanning will not work on Python 2.x)
* Bluez
    * sudo apt-get install bluez bluez-hcidump

## Installation

  - [Via Chef](chef/pybtsteward/README.md)
  - [One-Off](INSTALL.md)

## Configuration

  - Most of the configuration is outlined


## Upgrade

    sudo pip install PyBTSteward --upgrade

## Usage
	PyBTSteward [-s] [-t] [-o] [-v] [-V]

	optional arguments:
		-h, --help            show this help message and exit
		-u [URL], --url [URL] URL to advertise.
		-s, --scan            Scan for URLs.
		-t, --terminate       Stop advertising URL.
		-o, --one             Scan one URL only.
		-v, --version         Version of PyBTSteward.
		-V, --Verbose         Print lots of debug output.

