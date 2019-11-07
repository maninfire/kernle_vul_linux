#/bin/sh
#cd /home/kylin/code_vuln/
cp vulnerable_driver/src/vuln_driver.ko ./
#aarch64-linux-gnu-gcc test_smep.c -o test_smep -g --static
tar zcvf vuln_driver.tar.gz vuln_driver.ko
tar zcvf test_smep.tar.gz test_smep.ko
tar zcvf vdso_equity-server.tar.gz vdso_equity-server.ko

sudo mv vuln_driver.tar.gz pack
sudo mv test_smep.tar.gz pack
sudo mv vdso_equity-server.tar.gz pack