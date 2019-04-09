##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'T1069 Permission Groups Discovery',
                      'Description'   => %q{
                        Discovery:
                        Adversaries may attempt to find local system or domain-level groups and permissions settings. On Windows, examples of commands that can list groups are net group /domain and net localgroup using the Net utility. This module runs net group /domain, net group "Domain Admins" /domain, net localgroup, and net accounts /domain },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1069' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end


  def run_cmds()
    # begin
    cmds = ["net group /domain", 'net group "Domain Admins" /domain', "net localgroup", "net accounts /domain"]
    cmds.each do |cmd|
      run_cmd(cmd)
    end
  end

  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"
      run_cmds()
      print_good("Module T1069W execution successful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1069W execution failed.")
    end
   end
end
