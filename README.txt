README.txt
Calvin Yang
Georgios Karagiannis
Michael Tang
Roman Sodermans

FILES INCLUDED:
asgn4/README.txt
asgn4/DESGIN.pdf
asgn4/Encrypt/protectfile.c
asgn4/Encrypt/rijndael.c
asgn4/Encrypt/rijndael.h
Makefile for protectfile.c

usr/src/sys/fs/crptofs/.
usr/src/sys/sbin/mount_crytofs/.
Makefile for cryptofs

usr/src/sys/sys/rijndael.h
usr/src/sys/kern/rijndael.c

PROTECTFILE USAGE:
sudo ./protectfile <-e or -d> <k0> <k1> <file>

TO MOUNT CRYPTOFS:
1. Run sudo make install within usr/src/sys/sbin/mount_cryptofs
2. sudo mount_cryptofs <target directory> <mount point>
3. Make sure mount point is an empty directory

NOTE:
All modfied and added files can be found using a grep for "TEAM WINNING"
	grep -r "TEAM WINNING" ./