# symbolhunter

Uses Virtual Memory Introspection and heuristics to extract symbols and structure information from any QEMU Linux VM.

### Requirements
-	radare2
-	r2pipe (python package)
-	python3

### Setup

#### Install required software
Using libvirt and kvm under linux is the easiest way to get the tool working. Follow [this guide](https://linuxconfig.org/install-and-set-up-kvm-on-ubuntu-18-04-bionic-beaver-linux) to get a working environment. You can use virt-manager once it's all setup to manage your VMs.

Then you need to install the required software for SymbolHunter:
 
- Install `python3` and `python3-pip` using apt
- Install radare2 (follow [these](https://rada.re/r/down.html) instructions)
- run `pip3 install -r requirements.txt` to install the required packages

#### Running
You can run `virt-manager` to interactively create / manager virtual machines. For now make sure the VM only has 1 CPU.

If the vm hard drive you are importing is not a qcow2 then you will need to convert it with `qemu-img`
For example converting a vmdk file:
`qemu-img convert -f vmdk -O qcow2 <infile.vmdk> <outfile.qcow2>`

Start up your target VM, make sure it all works as expected.

Run `sudo virsh list` to get the name of your vm. Under certain circumstances `export LIBVIRT_DEFAULT_URI="qemu:///system"` might be necessary first to see the VM.
```
user@debianhyper:~$ sudo virsh list
 Id    Name                           State
----------------------------------------------------
 30    ubuntu1604                     running
```

Now to enable the gdbstub which is needed for the tool to connect to you need to run the following command:
`sudo virsh qemu-monitor-command --hmp ubuntu1604 --cmd gdbserver`
Change `ubuntu1604` to the name found in `virsh list` above.

### Basic Usage

First you will need an file of enums, because it is not really possible to retrieve enum information in this way. An example enum file from Debian 9 is provided in the repository.
Then, to extract symbols, run `python3 symbolhunter.py -e debian9_enums.json`.
The output should look like this:
```
user@debianhyper:~$ python symbolhunter.py -e debian9_enums.json
= attach 1 0
= attach 1 1
Searching 14 bytes in [0xffffffff80000000-0xffffffffffffffff]
[# ]INFO:root:Found linux banner: Linux version 4.9.0-11-amd64 (debian-kernel@lists.debian.org) (gcc version 6.3.0 20170516 (Debian 6.3.0-18+deb9u1) ) #1 SMP Debian 4.9.189-3+deb9u2 (2019-11-11)

Searching 10 bytes in [0xffffffff80000000-0xffffffffffffffff]
[# ]Searching 8 bytes in [0xffffffff80000000-0xffffffff81aaab3e]
[# ]INFO:root:init_task string pointer found at ffffffff81a85ff8

...etc
```

If everything goes to plan you should now have a `symbols.json` in the current working directory that can then be used as the symbol file for PyREBox (the volatility3 version).

### Dealing with errors

You might need to use the guess (-g) option for cases where not all structures were identified (typically file structures).
This is a complete bodge and is unlikely to give accurate results. 
