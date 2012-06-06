fuckPsn 0.7 by [drizzt@ibeglab.org](mailto:drizzt@ibeglab.org)
==============================================================

## Prerequisites

* CA27.cer, dev\_blind.pkg, fuckPsn-v0.7b.exe from [here](https://github.com/drizztbsd/fuckPsn/downloads)
* OpenPS3FTP v1.3 or later, you can download 1.5 from [here](http://psx-scene.com/forums/attachments/f149/26137d1299287039-openps3ftp-v1-2-openps3ftp-v1-5-zip)

## ChangeLog

**v0.7:** Add support for 4.11 spoofing  
**v0.6:** Use an empty consoleid. **Warning:** be sure to get **my** 0.6 version  
**v0.5:** Add support for firmwares older than 3.55  
**v0.4:** Don't use PS3DNS anymore

## Installation

1. Install dev\_blind.pkg and OpenPS3FTP on your PS3 (using FTP, external USB or what else)
2. Launch dev\_blind and make it mount the flash
3. Open OpenPS3FTP
4. Connect via FTP to PS3 (using username _root_ and password _openbox_)
5. Go to /dev\_blind/data/cert
6. Rename `CA27.cer` to `CA27.cer.bak`
7. Put my `CA27.cer` as `/dev_blind/data/cert/CA27.cer`
8. Set the PS3's PRIMARY and SECONDARY DNS server to your PC's IP address
9. Reboot your PS3
10. Start `fuckPsn-v0.7.exe`
12. Enjoy with PSN

## Warnings

If you have followed the OLD guide you need to rename the original `CA27.cer` to `CA27.cer.bak` and (my) `CA24.cer` to `CA27.cer` and you have to restore the old `CA24.cer`, by renaming `CA24.cer.bak` to `CA24.cer`  
This is needed since some games use the original `CA24.cer`  
If you lost original cert, you can take it [here](https://github.com/downloads/drizztbsd/fuckPsn/OriginalCerts.zip)

## FAQs

**Q:** fuckPSN does not start or prints "Address already in use" as error  
**A:** Close anything that is using port 80 or 443, try also to close skype and to [disable ICS](http://forum.thewindowsclub.com/windows-7-management-support/28389-disable-ics-internet-connection-sharing-windows-7-a.html) if you are using it.

## Donate

If you like my work please [![Donate](https://www.paypal.com/en_GB/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=VGNL2G57YR6QJ)


## Using under Linux

1. Download [source code](https://github.com/drizztbsd/fuckPsn)
2. Install required gems with `gem install rubydns rainbow`
3. [Workaround] If you are using Ruby 1.9.3 you need to use a fixed RubyDNS version with `wget https://github.com/downloads/drizztbsd/fuckPsn/rubydns-0.3.4+ruby1.9.3.gem && gem install rubydns-0.3.4+ruby1.9.3.gem`
4. Launch fuckPsn: `sudo ./fuckPsn.rb`
5. Enjoy


## DEVELOPERS SECTION

### Build EXE (Windows only)

1. Install [Ruby for Windows](http://rubyinstaller.org/)
2. Install eventmachine beta `gem install eventmachine --pre`
3. Install required gems by opening the "Ruby Command Line" and typing `gem install ocra rainbow rubydns windows-pr win32console`
4. [Workaround] If you are using Ruby 1.9.3 you need to use a fixed RubyDNS version, so download https://github.com/downloads/drizztbsd/fuckPsn/rubydns-0.3.4+ruby1.9.3.gem and install it by typing `gem install rubydns-0.3.4+ruby1.9.3.gem`
5. Launch: `ocra --icon fuckPsn.ico fuckPsn.rb data\*`
6. You will have _fuckPsn.exe_ file
