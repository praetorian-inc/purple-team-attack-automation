#!/bin/bash

HOST_CMD="cmd /c calc.exe && echo T1023 > C:\\t1023.txt && whoami >> C:\\t1023.txt && date /t C:\\t1023.txt && time /t >> C:\\t1023.txt"

case $1 in
"x86"*)
  `msfvenom -p windows/exec CMD="${HOST_CMD}" -f exe -o t1023_x86.exe`
  ;;
"x64"*)
  `msfvenom -p windows/x64/exec CMD="${HOST_CMD}" -f exe -o t1023_x64.exe`
  ;;
*)
  echo ERROR: bad argument. Accepts x86 or x64.
  ;;
esac
