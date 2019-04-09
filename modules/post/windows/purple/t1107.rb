##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple
  include Msf::Post::Windows::Accounts
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'File Deletion (T1107) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion:
                        Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1107' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("MODULE", [ true, "Module to execute.", 'post/windows/manage/sdel']),
      OptBool.new('ZERO', [ false, 'Zero overwrite. If set to false, random data will be used', false]),
      OptInt.new('ITERATIONS', [false, 'The number of overwrite passes', 1 ]),
      OptString.new("FILE", [ true, "File to delete.", 'C:\\test.txt']),
      OptBool.new("CREATE", [ true, "Create the file if it doesn't exist?", true])
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['ZERO'] = datastore['ZERO']
      framework_mod.datastore['ITERATIONS'] = datastore['ITERATIONS']
      framework_mod.datastore['FILE'] = datastore['FILE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'RunAsJob'  => false)
  end

  def run
    begin
      return 0 if session.type != "meterpreter"

      file = datastore['FILE']
      mod = datastore['MODULE']

      unless is_admin?
        fail_with(Failure::NoAccess, "The current session does not have administrative rights.")
      end

      unless exists?(file)
        if datastore['CREATE']

          cmd = "'$str=\"T1107\"*1000|out-file #{file}'"
          print_status("loading powershell...")
          client.run_cmd("load powershell")
          print_status("Executing '#{cmd}' on #{session.inspect}")
          client.run_cmd("powershell_execute '#{cmd}'")
        else
          fail_with(Failure::NoAccess, "The current session does not have administrative rights.")
        end
      end


      print_status("Executing '#{mod}' on #{session.inspect}")
      run_module(mod)
      print_good("Module T1107W execution successful.")
    rescue ::Exception => e
        print_error("#{e.class}: #{e.message}")
        print_error("Module T1107W execution failed.")
    end
   end
end
