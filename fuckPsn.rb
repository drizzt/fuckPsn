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

$remoteHost = "199.108.4.73"

$remotePort = 443

puts "fuckPSN v0.3 by drizzt <drizzt@ibeglab.org>"
puts "target address: #{$remoteHost}:#{$remotePort}"

localHost = "0.0.0.0"
localPort = 443

$blockSize = 1024

cert_str = "-----BEGIN CERTIFICATE-----
MIICqjCCAhOgAwIBAgIBATANBgkqhkiG9w0BAQUFADBhMQswCQYDVQQGEwJJVDER
MA8GA1UECAwIVGVycm9uaWExITAfBgNVBAoMGFRoZSBCZXN0IENBIGluIHRoZSB3
b3JsZDEcMBoGA1UEAwwTc3V4LnBsYXlzdGF0aW9uLm5ldDAeFw0xMTAyMTIxMjIx
MDNaFw0xMjAyMTIxMjIxMDNaMFgxCzAJBgNVBAYTAklUMREwDwYDVQQIDAhUZXJy
b25pYTERMA8GA1UECgwIU3RlYWwgbWUxIzAhBgNVBAMMGmF1dGgubnAuYWMucGxh
eXN0YXRpb24ubmV0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDeaCWUD+YV
CMt8SelBscJndsib6Xhzd3kDP4lHydkCiIvoVq5YLMmKPkAH5WFCVJUMIDzkwFLX
EIb897hrFcP44eejcS22TP3I4PfQfTMcHBJjyzbbPkrL84Uhnwm7w8Tr2QbKzEie
YXDRrUDJKPvLS7pI3pircYIhpNNh9JKZOQIDAQABo3sweTAJBgNVHRMEAjAAMCwG
CWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNV
HQ4EFgQUTrI+noNYNyq6SW9tPiOMwW0qcOUwHwYDVR0jBBgwFoAU3F6SP7pK/OXO
WPBZOluGVUb4EOcwDQYJKoZIhvcNAQEFBQADgYEAsOCS11P2ngyn4YqigZedyiAL
5tZnIibJ90nTrmQ++HybBj9JQA3aM1CEx+F8xRlcEnCR3jLLXgf3E1fM3s2Do6es
iEyfqMtBrMcuoNNqzwSk3wgTYNS3NDkVczRVwpMS0Nn6OIBW+2XkloQ/qUlJ9+yM
K1CQNuCkJc9ZPpETC+M=
-----END CERTIFICATE-----"

key_str = "-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAN5oJZQP5hUIy3xJ
6UGxwmd2yJvpeHN3eQM/iUfJ2QKIi+hWrlgsyYo+QAflYUJUlQwgPOTAUtcQhvz3
uGsVw/jh56NxLbZM/cjg99B9MxwcEmPLNts+SsvzhSGfCbvDxOvZBsrMSJ5hcNGt
QMko+8tLukjemKtxgiGk02H0kpk5AgMBAAECgYEA2qPRxXO3wZfqyt2yNIX20lXA
sx1a71BVI69TWsKA1u+7coW8USx+WKwHsHt8GIQkHk6W7l5vUcOKoKc6ofM8udrU
OxDnZ0xEKjFWSITWdR42pGr/qSRpxWHeuGRn9tCEL8DOXNHiAglHxRQpFybZKciI
PHH3lQu1y7ndzYGdTIECQQDxdais6+GFY+xWhrPfW2ANCHny61igOLNkeM9Eizfm
GhVmvqaUQo79i/qvoFVU/xYwdroqqqyIIJ1ljO77VTUJAkEA68zFLftdUGcG3UmG
RGdODdLj2a90cJQb/EBKOCFKzPqKdBXWrd/DkidvHrmqvvRG9GMfd9q4ZZ3eQYi0
oDr+sQJAYgOb283Idugv6JO3ckRaQhAdyJDmIevCTleH80/7+ei+pT1gyzAVcTCg
KyiPWvhNHpEjUuyDKqLqoW1LGTTmWQJBAKo1fuPpPXuLUxYrO6Nm2p357AU3tJqL
HwRgN/L6fS8nbwfKt9N84YQ/uON57Hm4hPtmDdILbO3VHhk6IABFdZECQHbC8Dvb
tfj5htbU+aGKykoAQGVBBdPVcSrl9ZzTsvC7yHJ1pPrID3Zy8cVNtDa7k43wEnXw
Kln4xhBcsEKap/0=
-----END PRIVATE KEY-----"

@list_str = "Dest=83;CompatibleSystemSoftwareVersion=3.2100-;
Dest=83;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;

Dest=84;CompatibleSystemSoftwareVersion=3.2100-;
Dest=84;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;

Dest=85;CompatibleSystemSoftwareVersion=3.2100-;
Dest=85;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;

Dest=86;CompatibleSystemSoftwareVersion=3.2100-;
Dest=86;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;

Dest=87;CompatibleSystemSoftwareVersion=3.2100-;
Dest=87;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;

Dest=88;CompatibleSystemSoftwareVersion=3.2100-;
Dest=88;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;

Dest=89;CompatibleSystemSoftwareVersion=3.2100-;
Dest=89;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;

Dest=8A;CompatibleSystemSoftwareVersion=3.2100-;
Dest=8A;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;

Dest=8B;CompatibleSystemSoftwareVersion=3.2100-;
Dest=8B;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;

Dest=8C;CompatibleSystemSoftwareVersion=3.2100-;
Dest=8C;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;

Dest=8D;CompatibleSystemSoftwareVersion=3.2100-;
Dest=8D;ImageVersion=00000000;SystemSoftwareVersion=3.2100;CDN=http://lolz.com;CDN_Timeout=30;"

cert = OpenSSL::X509::Certificate.new(cert_str) # (File::read(cert_file))
key = OpenSSL::PKey::RSA.new(key_str)  #(File::read(key_file))

@ctx = OpenSSL::SSL::SSLContext.new()
@ctx.key = key
@ctx.cert = cert

server = TCPServer.new(localHost, localPort)
webServer = TCPServer.new(localHost, 80)

port = server.addr[1]
addrs = server.addr[2..-1].uniq

puts "*** HTTPS listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"

port = webServer.addr[1]
addrs = webServer.addr[2..-1].uniq

puts "*** HTTP listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"

# abort on exceptions, otherwise threads will be silently killed in case
# of unhandled exceptions
#Thread.abort_on_exception = true

# have a thread just to process Ctrl-C events on Windows
# (although Ctrl-Break always works)
#Thread.new { loop { sleep 1 } }

def connThread(local)
	port, name = local.peeraddr[1..2]
	puts "*** receiving from #{name}:#{port}"

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
		ready = select([server,webServer], nil, nil)
		if ready[0].include? server
			Thread.start(server.accept) { |local| sslConnThread(local) }
		end
		if ready[0].include? webServer
			Thread.start(webServer.accept) { |local| connThread(local) }
		end
	end
end

# vim: set ts=4 sw=4 sts=4 tw=120
