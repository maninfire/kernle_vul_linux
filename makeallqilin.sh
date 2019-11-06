#/bin/sh
#cd /home/kylin/code_vuln/
cd /home/lier/code_vuln
#aarch64-linux-gnu-gcc test_smep.c -o test_smep -g --static
gcc exp_VDSO.c -o exp_VDSO -g
gcc test_smep.c -o test_smep -g
cd vulnerable_driver
make

#sudo insmod /home/lier/code_vuln/vulnerable_driver/src/vuln_driver.ko
sudo insmod /home/lier//work/new_vulnerable/code_vuln/vulnerable_driver/src/vuln_driver.ko
sudo chmod 777 /dev/vulnerable_device

