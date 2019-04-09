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
                      'Name'          => 'System Information Discovery (T1082) Linux - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        An adversary may attempt to get detailed information about the operating system and hardware,
                        including version, patches, hotfixes, service packs, and architecture. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'linux' ],
                      'SessionTypes'  => [ 'meterpreter' ],
                      'References'    => [ ['URL','https://attack.mitre.org/techniques/T1082/'] ]
                     ))
  end

  def run

    begin
      print_status("Obtaining Operating System information")
      results = cmd_exec('/bin/uname -a')
      print_good(results)
    rescue ::Exception => e
      print_error("Error getting operating system information: #{e.class} #{e}")
    end

    print_status("Obtaining Hardware Information")
    cmds = ["/usr/bin/lshw -short", "/usr/bin/lscpu"]
    cmds.each do |cmd|
      begin
        print_status("Executing command #{cmd}...")
        print_good(cmd_exec(cmd))
      rescue ::Exception => e
        print_error("Error runing command #{cmd}: #{e.class} #{e}")
      end
    end
  end
end
