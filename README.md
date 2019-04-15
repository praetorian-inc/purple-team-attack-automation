Metasploit [![Build Status](https://travis-ci.org/rapid7/metasploit-framework.svg?branch=master)](https://travis-ci.org/rapid7/metasploit-framework) [![Maintainability](https://api.codeclimate.com/v1/badges/943e398e619c09568f3f/maintainability)](https://codeclimate.com/github/rapid7/metasploit-framework/maintainability) [![Test Coverage](https://api.codeclimate.com/v1/badges/943e398e619c09568f3f/test_coverage)](https://codeclimate.com/github/rapid7/metasploit-framework/test_coverage) [![Docker Pulls](https://img.shields.io/docker/pulls/metasploitframework/metasploit-framework.svg)](https://hub.docker.com/r/metasploitframework/metasploit-framework/)
==
The Metasploit Framework is released under a BSD-style license. See
[COPYING](COPYING) for more details.

At Praetorian, we were seeking a way to automatically emulate adversary tactics in order to evaluate Detection and Response capabilities. While there are already a number of other automated tools in this space, we weren't satisfied with the flexibility of these frameworks. Hence, we chose to implement a number of these TTPs as Metasploit Framework `post` modules. As of this release, we've implemented a little over 100 TTPs as modules. Metasploit's advantage is its robust library, capability to interact with operating system APIs, and its flexible license. In addition, we're able to emulate the features of other tools such as in-memory .NET execution via leveraging Metasploit's `execute_powershell` functionality. This allows Blue Teams to ensure that their tools are alerting on the actual TTP behavior and not execution artifacts (such as encoded PowerShell).

This is a fork of the the latest version of Metasploit (as of 09Apr2019) pulled from: https://github.com/rapid7/metasploit-framework

We're open sourcing our work because we believe in solving the cybersecurity problem. By giving Blue Teams more tools to emulate adversary behavior, we hope to improve their capabilities and reduce the still very high average dwell time.

## Wiki

For detailed opertional usage guidance and a list of modules and changes, please view the [wiki](https://github.com/praetorian-inc/purple-team-attack-automation/wiki).

## Quickstart

Installation should follow the instructions for installing a Metasploit Docker environment:
https://github.com/rapid7/metasploit-framework/tree/master/docker

In general:
 - Install Docker
 - `git clone https://github.com/praetorian-inc/purple-team-attack-automation.git`
 - Edit `./docker-compose.local.override.yml` to reflect the LHOST of your local system similar to below.

```
version: '3'
services:
  ms:
    environment:
      # example of setting LHOST
      LHOST: [Your system's IP address]
    # example of adding more ports
    ports:
      - 8080:8080
      - 443:443
```

 - Add / Remove further ports or IP addresses as you see fit. Don't forget to change the LHOST to your own IP address.
 - `docker-compose build`
 - Start the container with `./docker/bin/msfconsole`

### Meterpreter Payloads

Praetorian recommends you utilize [the nightly installers](https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers) in order to run msfvenom to create your payloads.

### Common Errors

```
ERROR: Couldn't connect to Docker daemon at http+docker://localunixsocket - is it running?
```

Solved by
```
service docker start
```

## Future Work

* Integrate the container into a fork of [DetectionLab](https://github.com/clong/DetectionLab)
* Compare execution of CALDERA and MSF and how artifacts differ so we can improve adversary emulation
* Leverage the [MSFRPCD](https://metasploit.help.rapid7.com/docs/running-metasploit-remotely) to facilitate automatic attack chaining

## Contact

If you're interested in our Purple Team services, [please reach out to us](https://www.praetorian.com/contact).

If you're an engineer looking to join our great team, we have openings at [our careers page](https://www.praetorian.com/company/careers).

## Contributing

See the [Contribution Guide](https://github.com/praetorian-inc/purple-team-attack-automation/blob/master/CONTRIBUTING.md) for a step-by-step guide to making a module.

Also, follow the [Metasploit Framework's general contributing guidelines](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md).

## Acknowledgements

We'd like to thank various members of the security community for providing a lot of the techniques and code that we integrated into this project. 

* [MITRE ATT&CK&trade;](https://attack.mitre.org/) (Obviously)
* [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
* [@subtee](https://twitter.com/subTee)
* [LOLBAS Project](https://lolbas-project.github.io/)
* [CALDERA](https://github.com/mitre/caldera)

At Praetorian, the following engineers helped contribute modules:
* Josh Abraham `jabra [at] spl0it.org` and [@jabra](https://twitter.com/Jabra)
* Abraham Adberstein
* Tanner Harper
* Thomas Hendrickson [github.com/tomis007](github.com/tomis007)
* Dallas Kaman
* Blake Luther
* Matt Schneider
* Matthew Verrette
* Daniel Wyleczuk-Stern [@daniel_cybersec](https://twitter.com/Daniel_Cybersec)
