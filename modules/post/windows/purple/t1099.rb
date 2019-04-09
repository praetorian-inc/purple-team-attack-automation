##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::File
  include Msf::Post::Windows::Powershell

  def initialize(info={})

    super(update_info(info,
                      'Name'          => 'Timestomp (T1099) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion:
                        Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder. This is done, for example, on files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools. Timestomping may be used along with file name Masquerading to hide malware and tools.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1099' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new('FILE', [ true, 'File','C:\\\\t1099.txt']),
      OptString.new('DATE', [ true, 'File','12/31/1999 11:59 pm']),
      OptEnum.new('ATTRIBUTE', [true,  'File attribute', 'all', [ 'all', 'creationtime', 'lastaccesstime','lastwritetime']]),
      OptBool.new('CREATE', [ true, "Create file if it doesnt exist.", true]),
      OptBool.new('CLEANUP', [ true, "Delete the file after execution.", true])
    ])
  end

  def update_timestamp(file,attrib,date)
    cmd = "(Get-Item #{file}).#{attrib}=$(Get-Date \"#{date}\")"
    begin
        print_status("loading powershell...")
        client.run_cmd("load powershell")
        print_status("Executing '#{cmd}' on #{session.inspect}")
        client.run_cmd("powershell_execute '#{cmd}'")
        print_status("The file should now has an '#{attrib}' date of '#{date}'")
    rescue ::Exception => e
        print_error("Unable to execute: #{e.message}")
        return
    end
  end

  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"
      fail_with(Failure::NoAccess, "The current session does not have administrative rights.") unless is_admin?

      file = datastore['FILE']
      date = datastore['DATE']
      attrib = datastore['ATTRIBUTE']


      unless exists?(file)
        if datastore['CREATE']
          print_status("Creating file on #{session.inspect}")
          append_file(file,"TTP 1099")
        end
      else
        print_status("File already exists...")
      end

      if attrib == 'all'
        update_timestamp(file,'creationtime',date)
        update_timestamp(file,'lastaccesstime',date)
        update_timestamp(file,'lastwritetime',date)
      else
        update_timestamp(file,attrib,date)
      end

      if datastore['CLEANUP']
        print_status("Removing file...")
        rm_f(file)
      end

      print_good("Module T1099W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1099W execution failed.")
    end
  end
end
