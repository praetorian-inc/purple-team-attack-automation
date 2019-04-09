# Contributing
Thanks for your interest in helping Praetorian's Purple Team ATT&CK&trade; Automation Project!

Are you about to report a bug? Sorry to hear it. Here's our [Issue tracker](https://github.com/praetorian-inc/purple-team-attack-automation/issues).
Please try to be as specific as you can about your problem; include steps to reproduce (cut and paste from your console output if it's helpful) and what you were expecting to happen.

# Contributing to Purpleteam Automation

What you see here in CONTRIBUTING.md is a guide to contributing to our project. It'll walk you through, step-by-step, to making your own post module and submitting it for review.

# Intended Audience

This document is intended for people familiar with the following concepts
and technologies: `metasploit`, `git`, `ruby`, `Windows`, and `object-oriented programming`.
You don't need to know all the ins and outs, but a working knowlege of these is helpful.

# Project Structure

We are working off of a fork of Metasploit 5. All contributions for the moment should be in the following folders:

* `modules/post/windows/purple` for Windows TTPs
* `modules/post/linux/purple` for Linux TTPs
* `modules/post/osx/purple` for macOS TTPs
* `modules/post/multi/purple` for TTPs that can be utilized by multiple operating systems. TTPs that are network based (such as network scanning) should go here

All work is being done on the `master` branch. When working on a module, make a new branch off of `master` following the steps below, and make a pull request to merge your change into `master`.

Place data files (compiled exes, other scripts and payloads) in `data/purple/tXXXX/`. Make a new directory if working on a new payload. If submitting a compiled binary, please also include the source.

# Dev and Testing

We recommend you utilize a lab (such as https://github.com/clong/DetectionLab) to test TTPs.


# Testing and submitting

- To test your work, you can use `reload` and `reload all` in Metasploit to force it to reload the most recent code.
- Run ./tools/dev/msftidy.rb on your module and address any issues. There's a couple of warnings we're not concerned about:
- `~/purple-team-attack-automation/tools/dev/msftidy.rb . | grep -v CVE | grep -v license | grep -v download`

# Standards
Abide by the following standards and coding guidelines when building modules.

## Titles
Module name should be in the following format:
{MITRE title} ({MITRE #}) {OS} - Purple Team

## References

Please include a URL reference to the MITRE TTP number. Please give credit if you used code from other sources.

## Description

Copy the relevant portions of the description from MITRE. Add any other information needed for running the module.

## msftidy
Run ./tools/dev/msftidy.rb on a module before submitting for merge request. Make sure to fix all findings

## General

All files should write to the root of the primary drive

Cleanup should be default (except for Persistence)

Output the following line
`print_good("Module {{ttp #}} execution successful")`
or
`print_error("Module {{ttp #}} execution failed")`

## Begin/Rescue

Yes. We know it's not great to surrond your entire code block in a try/catch. Our dev team is shaking their heads. However, considering some of the weird errors that can occur when using Meterpreter payloads, we found that this made our error testing and catching a lot more efficient. We suggest you do the same.

## Execution

All execution modules should default to starting calc.exe

The module should check if calc is running first and kill it if it does

After starting calc, the module should confirm that calc is running and kill it before it reports success

## Persistence

Persistence modules should write a file to the root drive

The file should be titled txxxx.txt

The contents of the file should be:

```
txxxx
user context (output of whoami)
date (output from date /t)
time (output from time /t)
```

## .NET

If .NET code already exists for a TTP, feel free to convert it a DLL. Follow these directions.

https://github.com/praetorian-inc/purple-team-attack-automation/blob/master/Execute-Assembly.md

## PowerShell

Please utilize [Meterpreter's PowerShell extension](https://www.darkoperator.com/blog/2016/4/2/meterpreter-new-windows-powershell-extension). It is less likely to get flagged by AV/EDRs.

## EXEs and DLLs

Instead of using `msfvenom` please use compiled code (such as from a C, C++, .NET, etc project). Venom binaries are flagged and that prevents us from understanding
if the TTP behavior was detected vs simply being signature flagged by AV

## Purple Library

We created 3 functions to assist with automation.

kill_calc

run_cmd

check_for_calc

Information on these functions can be found in `lib/msf/core/post/windows/purlpe.rb`