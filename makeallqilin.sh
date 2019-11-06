#/bin/sh
#cd /home/kylin/code_vuln/
cd /home/greatwall/code_vuln
#aarch64-linux-gnu-gcc test_smep.c -o test_smep -g --static
gcc vdso_equity.c -o vdso_equity -g
gcc test_smep.c -o test_smep -g
cd vulnerable_driver
make

sudo insmod /home/greatwall/code_vuln/vulnerable_driver/src/vuln_driver.ko
#sudo insmod /home/lier//work/new_vulnerable/code_vuln/vulnerable_driver/src/vuln_driver.ko
sudo chmod 777 /dev/vulnerable_device

