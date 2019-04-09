##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Data Compressed (T1002) macOS - Purple Team',
      'Description'    => %q{
        Data Compressed: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network. The compression is done separately from the exfiltration channel and is performed using a custom program or algorithm, or a more common compression library or utility such as 7zip, RAR, ZIP, or zlib.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Praetorian' ],
      'Platform'       => [ 'osx' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1002' ] ],
      'SessionTypes'   => [ 'meterpreter' ]
     ))

   register_options(
    [
    OptString.new("SOURCE", [false, "Space separated names of files to compress. Use the full path.", "t1002.txt"]),
    OptString.new("DESTINATION", [false, "The full path and name to be given to the compressed file.", "/tmp/t1002"]),
    OptBool.new("TAR", [false, "Compress items into a tarball, rather than a zipfile.", false])
  ])
 end

  def run
    return 0 if session.type != "meterpreter"

    if(datastore['SOURCE'] == "t1002.txt")
      print_status("Attempting to create text file to compress.")
      create_first = cmd_exec("echo 'T1002-M' > 1.txt")

      if !create_first.blank?
        print_error create_first
        return
      end
    end

    if datastore['TAR']
      result = cmd_exec("tar -czvf #{datastore['SOURCE']} > #{datastore['DESTINATION']}")
      if !result.blank?
        print_error result
      end
    else
      result = cmd_exec("zip -r #{datastore['DESTINATION']} #{datastore['SOURCE']}")
      print_good result
    end

    print_good("Module finished with success!")

  end
end
