##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::CliParse

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Query Registry (T1012) Windows - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Adversaries may interact with the Windows Registry to gather
                       information about the system, configuration, and installed software. The
                       Registry contains a significant amount of information about the operating
                       system, configuration, software, and security. Some of the information may help
                       adversaries to further their operation within a network. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [
                        [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1002' ] ,
                        [ 'URL', 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    begin
      raise "Module requires Meterpreter session." if session.type != "meterpreter"

      cmd_list = ['reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"',
                  'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"',
                  'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"',
                  'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices"',
                  'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices"',
                  'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"',
                  'reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"',
                  'reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"',
                  'reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"',
                  'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"',
                  'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"',
                  'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"',
                  'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"',
                  'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"',
                  'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"',
                  'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"',
                  'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"']

      cmd_fails = {}
      cmd_list.each do |cmd|
        print_status("Executing '#{cmd}' on host.")
        result = cmd_exec(cmd)
        error_hash = win_parse_error(result)

        if error_hash[:error] != "Unknown Error"
          print_error "There was an issue executing the command:"
          print_error "\t#{error_hash[:error]}"
          cmd_fails["#{cmd}"] = "#{error_hash}"
        else
          print_line result
        end
      end

      if cmd_fails.length == cmd_list
        raise "All commands failed execution."
      elsif cmd_fails.length > 0
        print_warning("#{cmd_fails.length} of #{cmd_list.length} commands failed execution.")
      end

      print_good("Module T1012W execution successful.")

    rescue ::Exception => e
      print_error("#{e.message}")
      print_error("Module T1012W execution failed.")
    end
  end
end
