#!/bin/sh

set -e

apt-get -y install rubygems ruby1.8-dev libopenssl-ruby1.8 g++
gem install rubydns rainbow
rm -rf /usr/local/share/fuckPsn
mkdir -p /usr/local/share/fuckPsn
cd /usr/local/share/fuckPsn
wget -qO- https://github.com/drizztbsd/fuckPsn/tarball/master | tar --strip-components=1 -C /usr/local/share/fuckPsn -xzf -
printf '#!/bin/sh\ncd /usr/local/share/fuckPsn && exec /usr/bin/sudo ./fuckPsn.rb "$@"' > /usr/local/sbin/fuckPsn
chmod 0755 /usr/local/sbin/fuckPsn

if ! command -v ruby >/dev/null; then
	command -v ruby1.8 >/dev/null && sed -i '1s/ruby/&1.8/g' /usr/local/share/fuckPsn/fuckPsn.rb
fi

version=`grep '^FUCKPSN_VERSION=' fuckPsn.rb | cut -f 2 -d \'`
echo "fuckPsn v$version successfully installed!"
