0) You will need to pick TWO partners -- form groups of THREE

1) Download the files and directories for this lab to your laptop. 
   COPY YOUR AT_Master_TDC.db and NAT_Master_TDC.db INTO THIS DIRECTORY (from the previous lab)

NOTE: For ubuntu users. Be sure sqlite is installed on your laptop. You should have done this in the previous
   lab where you run device authentication only.
apt install sqlite3
apt install libsqlite3-dev

You must have openssl version 1.1.1 installed too. On my ubuntu machine, it is there by default. Check the version, type
openssl version

This should return
OpenSSL 1.1.1

2) Edit the Makefile and change the path to where you installed Vivado. For CORA, you will need to use a version
   of Vivado 2017.x, otherwise you will get an error 'GLIBC_2.28' not found.
   Run the command make

3) You will need a switch to connect your laptop to THREE FPGA boards, one TTP with IP 192.168.1.9 and the remaining two
with 192.168.1.10 and 192.168.1.11. Be sure to edit the /etc/network/interfaces file and change the 
   'iface eth0 inet static' section, e.g.,
        hwaddress ether 08:00:00:00:00:22
        address 192.168.1.10
        netmask 255.255.255.0
        gateway 192.168.1.1

   MAKE SURE the MAC address in hwaddress ether 08:00:00:00:00:22 is UNIQUE across all three boards
   MAKE SURE the IP address in address 192.168.1.10 is UNIQUE across all three boards, and assigned as above.

4) PROGRAM THE ZYBO OR CORA BOARD WITH ONE OF THE BITSTREAMS (ZYBO use 'echo' command, CORA use Hardware Manager in Vivado).

5) Copy the following files to your Zybo/Cora boards
scp TTP_DB.elf root@192.168.1.9:
scp device_regeneration.elf root@192.168.1.10:
scp device_regeneration.elf root@192.168.1.11:

scp Challenges.db root@192.168.1.9:
scp Challenges.db root@192.168.1.10:
scp Challenges.db root@192.168.1.11:

ZYBO:
scp ZYBO_LIBS/libsqlite3.so.0.8.6 root@192.168.1.10:/lib

CORA:
scp CORA_LIBS/libsqlite3.so.0.8.6 root@192.168.1.10:/lib

BOTH ZYBO AND CORA
scp ARM_LIBS/libcrypto.so.1.1 root@192.168.1.10:/lib
scp ARM_LIBS/libssl.so.1.1 root@192.168.1.10:/lib

6) After copying the libsqlite3.so.0.8.6, do the following on your Cora or Zybo boards
cd /lib
ln -s libsqlite3.so.0.8.6 libsqlite3.so.0
ln -s libsqlite3.so.0.8.6 libsqlite3.so
ln -s libcrypto.so.1.1 libcrypto.so
ln -s libssl.so.1.1 libssl.so
cd

7) YOU MUST PROGRAM THE BOARD BEFORE RUNNING THESE COMMANDS
ZYBO: Program with each of these, one-at-a-time, using the 'echo' command and run authentication
CORA: Program with each of these, one-at-a-time, from Vivado/Hardware Manager and run authentication

echo SR_RFM_V4_TDC_Macro_P1.bit.bin > /sys/class/fpga_manager/fpga0/firmware
echo SR_RFM_V4_TDC_Macro_P2.bit.bin > /sys/class/fpga_manager/fpga0/firmware
echo SR_RFM_V4_TDC_Macro_P3.bit.bin > /sys/class/fpga_manager/fpga0/firmware
echo SR_RFM_V4_TDC_Macro_P4.bit.bin > /sys/class/fpga_manager/fpga0/firmware

8) Copy PUFCash_V3.db and AuthenticationToken.db to your ZYBO or CORA board
   scp PUFCash_V3.db root@192.168.1.9:
   scp AuthenticationToken.db root@192.168.1.9:

   scp PUFCash_V3.db root@192.168.1.10:
   scp AuthenticationToken.db root@192.168.1.10:

   scp PUFCash_V3.db root@192.168.1.11:
   scp AuthenticationToken.db root@192.168.1.11:

9) Run this on your laptop FIRST, change the IP as needed:
verifier_regeneration Master_TDC SR_RFM_V4_TDC SRFSyn1 192.168.1.20 Master1_OptKEK_TVN_0.00_WID_1.75

   Wait for it to finish, i.e. to print 'Waiting for connections ...'

9) Run this on your Cora/Zybo, change the IP as needed
./TTP_DB.elf 192.168.1.9 192.168.1.20

10) Run these on your remaining two Cora/Zybo boards, change the IP as needed. Order does not matter and both
can be run simultaneously.
./device_regeneration.elf Alice 192.168.1.10 192.168.1.20
./device_regeneration.elf Bob 192.168.1.11 192.168.1.20

11) The Alice and Bob FPGAs will present you with a menu. 
   a) Choose Get-ATs (option 8) first on BOTH Alice and Bob's FPGAs. 
   b) Choose TRANSFER (Option 2) on either Alice or Bob (NOT BOTH). 

   This will eventually transfer money between Alice and Bob but right now, it only does mutual authentication 
   and session key generation.

12) Prepare to demo this in class. 

