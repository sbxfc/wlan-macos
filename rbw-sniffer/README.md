#How to use it?

	$make
	$./rbw_sniffer -i <interface name>

#Example

	$make
	$./rbw_sniffer -i en1

#Limitations

1,You need to open your WIFI network and make sure the BPF can access.

		sudo chmod 777 /dev/bpf*
