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

require 'rainbow'

gem 'rubydns', '~> 0.4.0'
require 'rubydns'

# Ocra is the .exe generator
if defined?(Ocra)
	require 'rexec/client'
	exit
end

# Enter in current directory
Dir.chdir File.dirname($0)

# Change 0.0.0.0 to your LAN IP if you want
localHost = "0.0.0.0"

# You don't need to edit below this comment!!

FUCKPSN_VERSION='1.0'
PLATFORM_VERSION='04.21'
PLATFORM_PASSPHRASE='zvci2hj3ccctzRxtZwbgarlroxtdhcoyotfywlzkbzjbzfz>azsjtuie'

puts "fuckPSN v#{FUCKPSN_VERSION}".color(:green) + " by drizzt <drizzt@ibeglab.org> ".color(:red) + "-- ".color(:cyan) + "https://github.com/drizzt/fuckPsn".color(:cyan)

# Listening ports
localSslPort = 443
localWebPort = 80
localDnsPort = 53

# PSN (auth.np.ac.playstation.net) IP address
$remoteHost = "173.230.216.161"
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
begin
	sslServer = TCPServer.new(localHost, localSslPort)
rescue Errno::EADDRINUSE
	$stderr.puts "Error".color(:red) + " Port " + localSslPort.to_s + " already in use"
end
begin
	webServer = TCPServer.new(localHost, localWebPort)
rescue Errno::EADDRINUSE
	$stderr.puts "Error".color(:red) + " Port " + localWebPort.to_s + " already in use"
end
begin
	dnsSocket = UDPSocket.new(Socket::AF_INET)
	dnsSocket.bind(localHost, localDnsPort)
rescue Errno::EADDRINUSE
	$stderr.puts "Error".color(:red) + " Port " + localDnsPort.to_s + " already in use"
end

if sslServer.nil? or webServer.nil? or dnsSocket.nil?
	exit 1
end

# Some prints
port = sslServer.addr[1]
addrs = sslServer.addr[2..-1].uniq

puts "Target Address: ".color(:green) + "#{$remoteHost}:#{$remotePort} - auth.np.ac.playstation.net".color(:yellow)
puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " [SSL]".color(:red) + " listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}".color(:green)

port = webServer.addr[1]
addrs = webServer.addr[2..-1].uniq

puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " [WEB]".color(:red) + " listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}".color(:green)

port = dnsSocket.addr[1]
addrs = dnsSocket.addr[2..-1].uniq

puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " [DNS]".color(:red) + " listening on #{addrs.collect{|a|"#{a}:#{port}" }.join(' ')}".color(:green)

# UDP Socket does per packet reverse lookups unless this is set.
UDPSocket.do_not_reverse_lookup = true

# abort on exceptions, otherwise threads will be silently killed in case
# of unhandled exceptions
#Thread.abort_on_exception = true

# have a thread just to process Ctrl-C events on Windows
# (although Ctrl-Break always works)
#Thread.new { loop { sleep 1 } }

R =  Resolv::DNS.new
IN = Resolv::DNS::Resource::IN

# Thread used for DNS connections
def dnsConnThread(local)
	packet, sender = local.recvfrom(1024*5)
	puts "*** ".color(:green) + "[DNS]".color(:red) + " receiving from #{sender.last}:#{sender[1]}".color(:green)
	myIp = UDPSocket.open {|s| s.connect(sender.last, 1); s.addr.last }
	RubyDNS::Server.new do |server|
		server.logger.level = Logger::INFO
		Thread.new do
			match("auth.np.ac.playstation.net", IN::A) do |transaction|
				logger.info("#{transaction} query received, returning #{myIp}")
				transaction.respond!(myIp)
			end

			match(/ps3.update.playstation.net$/, IN::A) do |match_data, transaction|
				logger.info("#{transaction} query received, returning #{myIp}")
				transaction.respond!(myIp)
			end

			otherwise do |transaction|
				transaction.passthrough!(R)
			end

			RubyDNS::UDPHandler::process(server, packet) do |result|
				local.send(result.encode, 0, sender[2], sender[1])
			end
		end
	end
	puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " [DNS]".color(:red) + " done with #{sender.last}:#{sender[1]}".color(:green)
end

# Thread used for HTTP connections
def webConnThread(local)
	port, name = local.peeraddr[1..2]
	puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " [WEB]".color(:cyan) + " receiving from #{name}:#{port}".color(:green)

	puts "[#{Time.new}] ".color(:cyan) + local.gets.color(:yellow)

	local.write("HTTP/1.1 200/OK\r\nContent-Type: text/plain\r\nContent-Length: #{@list_str.size}\r\n\r\n#{@list_str}").color(:green)
	local.close

	puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " [WEB]".color(:cyan) + " done with #{name}:#{port}".color(:green)
end

# Thread used for HTTPS connections
def sslConnThread(local)
	port, name = local.peeraddr[1..2]
	puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " [SSL]".color(:yellow) + " receiving from #{name}:#{port}".color(:green)

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
			puts "[#{Time.new}]".color(:cyan) + " timeout".color(:red)
			break
		end
		if ready[0].include? sslLocal
			# local -> remote
			begin
				data = sslLocal.sysread($blockSize)
			rescue EOFError
				puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " local end closed connection".color(:red)
				break
			end

			if data.match('consoleid')
				data.sub!(/consoleid=.*/, '00000000000000000000000000000000000000000000000000000000000000000000000001')
				puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " Spoofed consoleid".color(:red)
			end
			if data.match('X-Platform-Passphrase: ')
				data.sub!(/^X-Platform-Passphrase: .*/, 'X-Platform-Passphrase: ' + PLATFORM_PASSPHRASE)
				data.sub!(/^X-Platform-Version: PS3 .*/, 'X-Platform-Version: PS3_C ' + PLATFORM_VERSION)
			else
				data.sub!(/^X-Platform-Version: PS3 .*/, "X-Platform-Version: PS3_C #{PLATFORM_VERSION}\r\nX-Platform-Passphrase: #{PLATFORM_PASSPHRASE}")
			end
			sslRemote.write(data)
		end
		if ready[0].include? sslRemote
			# remote -> local
			begin
				data = sslRemote.sysread($blockSize)
			rescue EOFError
				puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " remote end closed connection".color(:red)
				break
			end
			sslLocal.write(data)
		end
	end

	sslLocal.close
	local.close
	sslRemote.close
	remote.close

	puts "*** ".color(:green) + "[#{Time.new}]".color(:cyan) + " [SSL]".color(:yellow) + " done with #{name}:#{port}".color(:green)
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
