##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'File Deletion (T1107) Linux - Purple Team',
                      'Description'   => %q{
                        Defense Evasion:
                        Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1107' ] ],
                      'Platform'      => [ 'linux' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptBool.new('ZERO', [ false, 'Zero overwrite. If set to false, random data will be used', false]),
      OptInt.new('ITERATIONS', [false, 'The number of overwrite passes', 1 ]),
      OptString.new("FILE", [ true, "File to delete.", '/test.txt']),
      OptBool.new("CREATE", [ true, "Create the file if it doesn't exist?", true])
    ])
  end

  def run
    return 0 if session.type != "meterpreter"

    file = datastore['FILE']

    unless exists?(file)
      if datastore['CREATE']

        cmd = "sudo /bin/echo T1107 sample file > #{file}"
        begin
          print_status("Executing '#{cmd}' on #{session.inspect}")
          res = cmd_exec(cmd)
          print_good("File created!")
        rescue ::Exception => e
          print_error("Unable to execute: #{e.message}")
          return
        end
      else
        fail_with(Failure::NoAccess, "File does not exist.")
      end
    end

    zero = datastore['ZERO']
    cmd = ''
    if zero
      cmd = "sudo /usr/bin/shred -f -z -n #{datastore['ITERATIONS']} #{file}"
    else
      cmd = "sudo /usr/bin/shred -f -n #{datastore['ITERATIONS']} #{file}"
    end

    begin
      print_status("Executing '#{cmd}' on #{session.inspect}")
      res = cmd_exec(cmd)
      print_good("Successful execution!")
    rescue ::Exception => e
        print_error("Unable to execute: #{e.message}")
        return
    end
   end
end
