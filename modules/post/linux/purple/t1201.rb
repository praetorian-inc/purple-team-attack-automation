##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Password Policy Discovery (T1201) Linux - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Password polies for networks are a way to enforce complex passwords that are difficult
                                          to guess or crack through Brute Force. An adversary may attempt to access detailed
                                          information about the password policy used within an enterprise network. This would help
                                          the adversary to create a list of common passwords and launch a dictionary and/or brute
                                          force attacks which adheres to the policy (e.g. if the minimum password lenght should be 8
                                          then not tryping passwords such as 'pass123'; not checking for more that 3-4 passwords per
                                          account if the lockout is set to 6 as to not lock out the accounts). },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'linux' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1201' ] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run

    distro = get_sysinfo

    return 0 if session.type != "meterpreter"

    begin
      print_status("Examine password expiration policy - Linux")
      print_good(cmd_exec("/bin/cat /etc/login.defs"))
    rescue ::Exception => e
      print_error("Error running command: #{e.class} #{e}")
    end

    case distro
    when /ubuntu/
      begin
        print_status("Examine password complexity policy - Ubuntu")
        print_good(cmd_exec("/bin/cat /etc/pam.d/common-password"))
      rescue ::Exception => e
        print_error("Error running command: #{e.class} #{e}")
      end

    when /fedora|redhat/
      begin
        print_status("Examine password complexity policy - CENTOS/RHEL")
        print_good(cmd_exec("/bin/cat /etc/security/pwquality.conf"))
        print_good(cmd_exec("/bin/cat /etc/pam.d/system-auth"))
      rescue ::Exception => e
        print_error("Error running command: #{e.class} #{e}")
      end

    end
  end
end
