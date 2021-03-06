##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary
	
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
				OptString.new('VENUEID', [ true, 'foursquare venueid', '185675']), #Louve Paris France
				
				# 8
				OptString.new('USERNAME', [ true, 'foursquare username', 'username']),
				OptString.new('PASSWORD', [ true, 'foursquare password', 'password']),
			], self.class)
	
	end

	def run
	
		begin
			# 4
			user  = datastore['USERNAME']
			pass  = datastore['PASSWORD']
			venid = datastore['VENUEID']
			user_pass = Rex::Text.encode_base64(user + ":" + pass)
			decode    = Rex::Text.decode_base64(user_pass)
			postrequest = "twitter=1\n" #add facebook=1 if you want facebook

			print_status("Base64 Encoded User/Pass: #{user_pass}") #debug
			print_status("Base64 Decoded User/Pass: #{decode}") #debug

			# 5
			res = send_request_cgi({
				'uri'     => "/v1/checkin?vid=#{venid}",
				'version' => "1.1",
				'method'  => 'POST',
				'data'    => postrequest,
				'headers' =>
					{
						'Authorization' => "Basic #{user_pass}",
						'Proxy-Connection' =>  "Keep-Alive",
					}
			}, 25)
			
			# 6
			print_status("#{res}") #this outputs entire response, could probably do without this but its nice to see whats going on
			end

		# 7
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE =>e
			puts e.message
	end
end

