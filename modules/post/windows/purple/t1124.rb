##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'System Time Discovery (T1124) Windows - Purple Team',
        'Description'   => %q{
          Discovery:
          The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization
          between systems and services in an enterprise network.
          An adversary may gather the system time and/or time zone from a local or remote system. This
          information may be gathered in a number of ways, such as with Net on Windows by performing net
          time \\\\hostname to gather the system time on a remote system.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"

      cmd = "net time \\\\localhost"
      run_cmd(cmd)

      print_good("Module T1124W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1124W execution failed.")
    end
  end
end
