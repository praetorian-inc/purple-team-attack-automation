##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple
  include ::Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Peripheral Device Discovery (T1120) Windows - Purple Team',
        'Description'   => %q{
          Discovery:
          Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system.
          The information may be used to enhance their awareness of the system and network environment or may be used for further actions.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ],
        'References'    => [ 'https://attack.mitre.org/wiki/Technique/T1120' ]
    ))

    register_options(
      [
        OptString.new('PSH_SCRIPT', [ false, 'Powershell command to execute.', "gwmi Win32_USBControllerDevice | %{[wmi]($_.Dependent)} | Sort Manufacturer,Description,DeviceID | Ft -GroupBy Manufacturer Description,Service,DeviceID"]),
        OptString.new('CMD', [ false, 'CMD command to execute.', 'wmic path cim_logicaldevice where "Description like \'USB%\'" get /value']),
        OptBool.new('PSH', [true, 'Use PowerShell instead of CMD. Set to false if encoded PowerShell is being blocked.', true])
      ])
  end

  def run
    begin
      raise "Module requires meterpreter session" unless session.type == 'meterpreter'

      psh_script = datastore['PSH_SCRIPT']
      cmd = datastore['CMD']
      psh = datastore['PSH']

      if psh
        print_status("Loading powershell...")
        client.run_cmd("load powershell")
        print_status("Executing #{psh_script} on #{session.info}")
        client.run_cmd("powershell_execute '#{psh_script}'")
      else
        print_status("Execution #{cmd} on #{session.info}")
        run_cmd(cmd)
      end

      print_good("Module T1120 execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1120 execution failed.")
    end
  end

end
