#!/bin/sh

set -e

apt-get install rubygems
gem install rubydns rainbow
rm -rf /usr/local/share/fuckPsn
mkdir -p /usr/local/share/fuckPsn
cd /usr/local/share/fuckPsn
wget -qO- https://github.com/drizztbsd/fuckPsn/tarball/master | tar --strip-components=1 -C /usr/local/share/fuckPsn -xzf -
printf '#!/bin/sh\ncd /usr/local/share/fuckPsn && exec /usr/bin/sudo ./fuckPsn.rb "$@"' > /usr/local/sbin/fuckPsn
chmod 0755 /usr/local/sbin/fuckPsn

echo 'fuckPsn successfully installed!'
