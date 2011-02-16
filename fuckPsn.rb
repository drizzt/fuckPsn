#!/usr/bin/env ruby
#
# fuckPsn -- PSN version spoofer
#
# Copyright (C) drizzt <drizzt@ibeglab.org>
#
# This software is distributed under the terms of the GNU General Public
# License ("GPL") version 3, as published by the Free Software Foundation.
#

require 'rubygems'

require 'socket'
require 'openssl'

require 'rubydns'

# Ocra is the .exe generator
defined?(Ocra) and exit

# Enter in current directory
Dir.chdir File.dirname($0)

# Change 0.0.0.0 to your LAN IP if you want
localHost = "0.0.0.0"

# You don't need to edit below this comment!!
puts "fuckPSN v0.4 by drizzt <drizzt@ibeglab.org>"

# Listening ports
localSslPort = 443
localWebPort = 80
localDnsPort = 53

# PSN (auth.np.ac.playstation.net) IP address
$remoteHost = "199.108.4.73"
$remotePort = 443

$blockSize = 1024

# Initialize OpenSSL library
cert_file = File.join("data", "cert.pem")
key_file = File.join("data", "cert.key")
list_file = File.join("data", "ps3-updatelist.txt")

cert = OpenSSL::X509::Certificate.new(File::read(cert_file))
key = OpenSSL::PKey::RSA.new(File::read(key_file))
@list_str = File::read(list_file)

@ctx = OpenSSL::SSL::SSLContext.new()
@ctx.key = key
@ctx.cert = cert

# Start servers
sslServer = TCPServer.new(localHost, localSslPort)
webServer = TCPServer.new(localHost, localWebPort)
dnsSocket = UDPSocket.new(Socket::AF_INET)
dnsSocket.bind(localHost, localDnsPort)

# Some prints
port = sslServer.addr[1]
addrs = sslServer.addr[2..-1].uniq

puts "target address: #{$remoteHost}:#{$remotePort}"
puts "*** HTTPS listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"

port = webServer.addr[1]
addrs = webServer.addr[2..-1].uniq

puts "*** HTTP listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"

port = dnsSocket.addr[1]
addrs = dnsSocket.addr[2..-1].uniq

puts "*** DNS listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"

R =  Resolv::DNS.new

# UDP Socket does per packet reverse lookups unless this is set.
UDPSocket.do_not_reverse_lookup = true

# abort on exceptions, otherwise threads will be silently killed in case
# of unhandled exceptions
#Thread.abort_on_exception = true

# have a thread just to process Ctrl-C events on Windows
# (although Ctrl-Break always works)
#Thread.new { loop { sleep 1 } }

# Thread used for DNS connections
def dnsConnThread(local)
	packet, sender = local.recvfrom(1024*5)
	puts "*** [DNS] receiving from #{sender.last}:#{sender[1]}"
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
	puts "*** [DNS] done with #{sender.last}:#{sender[1]}"
end

# Thread used for HTTP connections
def webConnThread(local)
	port, name = local.peeraddr[1..2]
	puts "*** [WEB] receiving from #{name}:#{port}"

	puts local.gets

	local.write("HTTP/1.1 200/OK\r\nContent-Type: text/plain\r\nContent-Length: #{@list_str.size}\r\n\r\n#{@list_str}")
	local.close

	puts "*** [WEB] done with #{name}:#{port}"
end

# Thread used for HTTPS connections
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
			if data.match('X-Platform-Passphrase: ')
				data.sub!(/^X-Platform-Version: PS3 .*/, 'X-Platform-Version: PS3 03.56')
			else
				data.sub!(/^X-Platform-Version: PS3 .*/, "X-Platform-Passphrase: saktdlMapxsbsghmq5dhlwrmtsicyijmzntqaLcpgd8ybbetdmsha=jm\r\nX-Platform-Version: PS3 03.56")
			end
			sslRemote.write(data)
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

loop do
	# whenever server.accept returns a new connection, start
	# a handler thread for that connection
	ready = select([sslServer, webServer, dnsSocket], nil, nil)
	if ready[0].include? sslServer
		Thread.start(sslServer.accept) { |local| sslConnThread(local) }
	end
	if ready[0].include? webServer
		Thread.start(webServer.accept) { |local| webConnThread(local) }
	end
	if ready[0].include? dnsSocket
		Thread.start(dnsSocket) { |local| dnsConnThread(local) }
	end
end

# vim: set ts=4 sw=4 sts=4 tw=120
