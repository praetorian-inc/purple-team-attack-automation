##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Windows Management Instrumentation (T1047) Windows - Purple Team',
                      'Description'   => %q{
                        Execution:
                        Windows Management Instrumentation (WMI) is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) and Remote Procedure Call Service (RPCS) for remote access. RPCS operates over port 135
                                            },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1047' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("METHOD", [ true, "0=All, 1=Spawn a process, 2=Gather information about a system", '1']),
      OptBool.new("CLEANUP", [true, "Cleanup calc after execution.", true])
    ])
  end


  def run
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"

      case datastore['METHOD']
      when '0'
        t1047_exec()
        t1047_gather()
      when '1'
        t1047_exec()
      when '2'
        t1047_gather()
      else
        raise "Invalid method selected."
      end

      print_good("Module T1047 execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1047 execution failed.")
    end
   end


  def t1047_gather
    wmic_recon_commands = [
      "wmic useraccount get /ALL",
      "wmic process get caption,executablepath,commandline",
      "wmic qfe get description,installedOn /format:csv"]

    print_status("Executing WMIC information gathering commands.")
    wmic_recon_commands.each do |cmd|
      run_cmd(cmd)
    end
  end

  def t1047_exec(psh=false)
  #
  # Execute a process call create command using either CMD or powershell.
  # The default behavior is to default to CMD, then try powershell if no
  # running calc process is found.
  # Will try cmd -> psh, but not psh -> cmd (just does psh -> exit)
  #
    print_status("Killing existing instances of calc...")
    kill_calc

    # run a WMIC command to spawn calc
    cmd = "wmic process call create C:\\Windows\\System32\\calc.exe"
    print_status("Executing #{cmd} on #{session.inspect} using " + (psh ? "powershell" : "cmd"))
    # execute via powershell or cmd
    if psh
      print_status("Loading PowerShell")
      client.run_cmd("load powershell")
      print_status("Executing #{cmd} on #{session.inspect}")
      client.run_cmd("powershell_execute #{cmd}")
    else
      run_cmd(cmd)
    end

    # process can take a sec to spawn
    Rex::sleep(2)

    # check to see that calc was spawned
    # sometimes cmd can fail, if it does then try again with powershell
    if not check_for_calc and psh
      print_warning("Trying again using powershell...")
      t1047_exec(true)
    end

  end
end
