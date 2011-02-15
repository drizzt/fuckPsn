#!/usr/bin/env ruby
#
# fuckPsn -- PSN version spoofer
#
# Copyright (C) drizzt <drizzt@ibeglab.org>
#
# This software is distributed under the terms of the GNU General Public
# License ("GPL") version 3, as published by the Free Software Foundation.
#

require 'socket'
require 'openssl'

require 'rubydns'

$remoteHost = "199.108.4.73"
$remotePort = 443

puts "fuckPSN v0.4 by drizzt <drizzt@ibeglab.org>"
puts "target address: #{$remoteHost}:#{$remotePort}"

localHost = "0.0.0.0"
localPort = 443

$blockSize = 1024

cert_file = "cert.pem"
key_file = "cert.key"
list_file ="ps3-updatelist.txt"

cert = OpenSSL::X509::Certificate.new(File::read(cert_file))
key = OpenSSL::PKey::RSA.new(File::read(key_file))
@list_str = File::read(list_file)

@ctx = OpenSSL::SSL::SSLContext.new()
@ctx.key = key
@ctx.cert = cert

server = TCPServer.new(localHost, localPort)
webServer = TCPServer.new(localHost, 80)

dnsSocket = UDPSocket.new(Socket::AF_INET)
dnsSocket.bind(localHost, 53)
R =  Resolv::DNS.new

port = server.addr[1]
addrs = server.addr[2..-1].uniq

puts "*** HTTPS listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"

port = webServer.addr[1]
addrs = webServer.addr[2..-1].uniq

puts "*** HTTP listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"

port = dnsSocket.addr[1]
addrs = dnsSocket.addr[2..-1].uniq

puts "*** DNS listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"


# abort on exceptions, otherwise threads will be silently killed in case
# of unhandled exceptions
#Thread.abort_on_exception = true

# have a thread just to process Ctrl-C events on Windows
# (although Ctrl-Break always works)
#Thread.new { loop { sleep 1 } }

def dnsConnThread(local)
	packet, sender = local.recvfrom(1024*5)
	myIp = UDPSocket.open {|s| s.connect(sender.last, 1); s.addr.last }
	RubyDNS::Server.new do |server|
		server.logger.level = Logger::INFO
		Thread.new do
			match("auth.np.ac.playstation.net", :A) do |transaction|
				logger.info("#{transaction} query received, returning #{myIp}")
				transaction.respond!(myIp)
			end

			match(/ps3.update.playstation.net$/, :A) do |match_data, transaction|
				logger.info("#{transaction} query received, returning #{myIp}")
				transaction.respond!(myIp)
			end

			otherwise do |transaction|
				transaction.passthrough!(R)
			end

			result = server.receive_data(packet)
			local.send(result, 0, sender[2], sender[1])
		end
	end
end

def connThread(local)
	port, name = local.peeraddr[1..2]
	puts "*** receiving from #{name}:#{port}"

	puts local.gets

	local.write("HTTP/1.1 200/OK\r\nContent-Type: text/plain\r\nContent-Length: #{@list_str.size}\r\n\r\n#{@list_str}")
	local.close

	puts "*** done with #{name}:#{port}"
end

def sslConnThread(local)
	port, name = local.peeraddr[1..2]
	puts "*** [SSL] receiving from #{name}:#{port}"

	sslLocal = OpenSSL::SSL::SSLSocket.new(local, @ctx)
	sslLocal.accept

	# open connection to remote server
	remote = TCPSocket.new($remoteHost, $remotePort)

	sslRemote = OpenSSL::SSL::SSLSocket.new(remote)
	sslRemote.connect

	# start reading from both ends
	loop do
		ready = select([sslLocal, sslRemote], nil, nil, 120)
		if ready.nil?
			puts "timeout"
			break
		end
		if ready[0].include? sslLocal
			# local -> remote
			begin
				data = sslLocal.sysread($blockSize)
			rescue EOFError
				puts "local end closed connection"
				break
			end

			sslRemote.write(data.sub('X-Platform-Version: PS3 03.55', 'X-Platform-Version: PS3 03.56'))
		end
		if ready[0].include? sslRemote
			# remote -> local
			begin
				data = sslRemote.sysread($blockSize)
			rescue EOFError
				puts "remote end closed connection"
				break
			end
			sslLocal.write(data)
		end
	end

	sslLocal.close
	local.close
	sslRemote.close
	remote.close

	puts "*** [SSL] done with #{name}:#{port}"
end

if not defined?(Ocra)
	loop do
		# whenever server.accept returns a new connection, start
		# a handler thread for that connection
		ready = select([server, webServer, dnsSocket], nil, nil)
		if ready[0].include? server
			Thread.start(server.accept) { |local| sslConnThread(local) }
		end
		if ready[0].include? webServer
			Thread.start(webServer.accept) { |local| connThread(local) }
		end
		if ready[0].include? dnsSocket
			Thread.start(dnsSocket) { |local| dnsConnThread(local) }
		end
	end
end

# vim: set ts=4 sw=4 sts=4 tw=120
