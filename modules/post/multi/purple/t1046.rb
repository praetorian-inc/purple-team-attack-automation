##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post

    def initialize(info={})
      super(update_info(info,
                        'Name'          => 'Network Service Scanning (T1046) All - Purple Team',
                        'Description'   => %q{
                              Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system. },
                        'License'       => MSF_LICENSE,
                        'Author'        => [ 'Praetorian' ],
                        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1046' ] ],
                        'Platform'      => [ 'win', 'osx', 'linux' ],
                        'SessionTypes'  => [ 'meterpreter' ]
                       ))
      register_options(
      [
        OptString.new('MODULE', [true, "Scanner module to use (ack, syn, tcp, xmas)", "tcp"]),
        OptAddressRange.new('RHOSTS', [true, 'IP Range to scan']),
        OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
        OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000]),
        OptInt.new('CONCURRENCY', [true, "The number of concurrent ports to check per host", 10]),
        OptInt.new('DELAY', [true, "The delay between connections, per thread, in milliseconds", 0]),
        OptInt.new('JITTER', [true, "The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.", 0]),
      ])
    end

    def all_platforms
      Msf::Module::Platform.subclasses.collect {|c| c.realname.downcase }
    end

    def run_module(mod)
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['RHOSTS'] = datastore['RHOSTS']
      framework_mod.datastore['PORTS'] = datastore['PORTS']
      framework_mod.datastore['TIMEOUT'] = datastore['TIMEOUT']
      framework_mod.datastore['CONCURRENCY'] = datastore['CONCURRENCY']
      framework_mod.datastore['DELAY'] = datastore['DELAY']
      framework_mod.datastore['JITTER'] = datastore['JITTER']
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'Quiet' => false,
          'RunAsJob'  => false)

      select(nil,nil,nil,2)
    end

    def run_autoroute
      mod = 'post/multi/manage/autoroute'
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'Quiet' => false,
          'RunAsJob'  => false)
    end

    def run
      return 0 if session.type != "meterpreter"

      print_status("Running autoroute")
      run_autoroute()

      mod_base = 'auxiliary/scanner/portscan/'

      mod = datastore['MODULE']

      if mod == "tcp"
        mod_base = mod_base + mod
      elsif mod == "ack"
        mod_base = mod_base + mod
      elsif mod == "syn"
        mod_base = mod_base + mod
      elsif mod == "xmas"
        mod_base = mod_base + mod
      else
        print_error("Invalid module selected")
        return 0
      end

      begin
        print_status("Executing '#{mod_base}' on #{session.inspect}")
        run_module(mod_base)
        print_good("Successful execution!")
      rescue ::Exception => e
          print_error("Unable to execute: #{e.message}")
          return
      end

    end
  end
