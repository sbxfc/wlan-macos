#下载libpcap

- <http://www.tcpdump.org/>

#安装

	$cd libpcap-1.7.4
	$./configure
	$make
	$sudo make install

#编译&运行

	$cd /进入src目录
	$gcc main.c -o test -lpcap
	$sudo ./test -I en1(支持wlan的网卡接口名)

#问题

*Could not initialize a IEEE802_11_RADIO packet capture for interface XXX*

	1),检查你的WIFI是否打开
	2),设置一下bpf的访问权限

		sudo chmod 777 /dev/bpf*
