#/bin/sh
cd /home/greatwall/code_vuln/
cp vulnerable_driver/src/vuln_driver.ko ./
#aarch64-linux-gnu-gcc test_smep.c -o test_smep -g --static
gcc test_smep.c -o test_smep -g
gcc vdso_equity.c -o vdso_equity -g
gcc vdso_equity-server.c -o vdso_equity-server -g

cd vulnerable_driver
make

sudo insmod src/vuln_driver.ko
sudo chmod 777 /dev/vulnerable_device




