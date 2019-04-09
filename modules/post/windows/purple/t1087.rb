#
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super( update_info( info,
            'Name'          => 'Account Discovery (T1087) Windows - Purple Team',
            'Description'   => %q{
              Discovery:
              Adversaries may attempt to get a listing of local system or domain accounts. Windows
              Example commands that can acquire this information are net user,
              net group <groupname>, and net localgroup <groupname> using the Net utility or
              through use of dsquery. If adversaries attempt to identify the primary user,
              currently logged in user, or set of users that commonly uses a system, System
              Owner/User Discovery may apply. },
            'License'       => MSF_LICENSE,
            'Author'        => [ 'Praetorian' ],
            'Platform'      => %w{ win },
            'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1087' ] ],
            'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    begin
      raise "Module requires meterpreter session" if not session.type == 'meterpreter'

      cmd = ['net user', 'net group "Domain Admins" /DOMAIN', 'net localgroup Administrators']
      cmd.each do |cmd|
        print_status("Executing #{cmd} on #{session.inspect}...")
        result = cmd_exec(cmd)
        if not result.nil? and not result.empty?
          print_status(result)
        else
          print_warning("No output recorded.")
        end
      end

      print_good("Module T1087W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1087W execution failed.")
    end
  end
end
