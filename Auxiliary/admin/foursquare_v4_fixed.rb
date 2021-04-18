##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'


class MetasploitModule < Msf::Auxiliary
	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report

	def initialize
		super(
			# 2
			'Name'        	=> 'Foursquare Location Poster',	
			'Version'     	=> '$Revision:$',
			'Description'	=> 'Fuck with Foursquare, be anywhere you want to be by venue id',
			'Author'        => ['CG'],
			'License'	=> MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'http://groups.google.com/group/foursquare-api' ],
					[ 'URL', 'http://www.mikekey.com/im-a-foursquare-cheater/'],
				]
		)
#todo pass in geocoords instead of venueid, create a venueid, other tom foolery
		register_options(
			[
				# 3 
				Opt::RHOST('api.foursquare.com'),
				Opt::RPORT(443),  # foursquare api port
				OptString.new('SSL', [ false, "Negotiate SSL/TLS for outgoing connections", true ]), # required by foursquare api
				
				OptString.new('VENUEID', [ true, 'foursquare venueid', '185675']), #Louve Paris France
				
				# 8 
				# you should genarate oauth token from https://developer.foursquare.com with create your own app
				OptString.new('OAUTH_TOKEN', [ true, 'foursquare oauth2 token', 'oauth_token']),
  			], self.class)
	end
	
	def run
	
		begin
			# 4
			user = datastore['USERNAME']
			pass = datastore['PASSWORD']
			venueid = datastore['VENUEID']
            oauth_token = datastore['OAUTH_TOKEN']
			#user_pass = Rex::Text.encode_base64(user+":"+pass)
			user_pass = Rex::Text.encode_base64(oauth_token)
			decode = Rex::Text.decode_base64(user_pass)
			postrequest = "twitter=1\n" #add facebook=1 if you want facebook

			print_status("Base64 Encoded User/Pass: #{user_pass}") #debug
			print_status("Base64 Decoded User/Pass: #{decode}") #debug

			# 5
			res = send_request_cgi({
				'uri'     => "/v2/checkins/add?oauth_token=#{oauth_token}&v=20170215&venueId= #{venueid}",
				'version' => "1.1",
				'method'  => 'POST',
			}, 25)
			
			# 6
			print_status("#{res}") #this outputs entire response, could probably do without this but its nice to see whats going on
			end

		# 7
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE => e
			puts e.message
	end
end
