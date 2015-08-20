# Match interface: accelerating VXLAN with match interface
###### 2015-08-19


## Introduction

This is annotated example of how to get VXLAN working and then using match interface to use the hardware for encap/decap VXLAN headers. This falls somewhere between generating packets with your favorite packet generating tool and a real-life working example with a controller. Specifically by this I mean there are some hard coded values for MAC addresses and IP addresses and what not.

This is intended to be an informal write-up.

## Basics

For this we are using the fm10k driver with UIO support. Note this is not the same as fm10k driver that is included with released kernels. To load the driver use either 'insmod' or 'modprobe'

```
# insmod ./fm10k.ko
```

The simplest way I know to check for UIO support is to verify fm10k linked with uio.

```
# lsmod|grep fm10k
fm10k                 115316  1
vxlan                  37619  1 fm10k
uio                    19360  3 fm10k
ptp                    18933  2 fm10k,e1000e
```

The critical line is 'uio'. If that is missing then the driver is not built or does not support UIO.
UIO is out of scope for this document but is used to map the PCI bars into userspace for match interface.

Next start matchd,

```
# matchd -s
```

The '-s' is required to put all ports in the default VLAN group. 'matchd' does not support a daemon mode yet so it will not return from the command prompt. Users can either start it in the background or in another terminal. Starting it in another terminal and launching with the verbose '-v' option allows the user to see useful information describing how/ when the hardware is being programmed. To start in the background use '&' like,

```
# matchd -s &
```
Once 'matchd' is started its worth running a few basic test to verify it is up and running.

```
# match get_actions
       1: set_egress_port ( u32 egress_port )
       13: drop_packet (  )
       14: route_via_ecmp ( u16 ecmp_group_id )
       15: route ( u64 newDMAC, u16 newVLAN )
       3: set_dst_mac ( u64 mac_address )
       2: set_src_mac ( u64 mac_address )
       5: set_ipv4_dst_ip ( u32 ip_address )
       6: set_ipv4_src_ip ( u32 ip_address )
       10: set_udp_src_port ( u16 port )
  ...
```

The above command will list all the actions the attached device supports. If this works the basics are up and running.

## Test Environment

The test environment for this example is a fm10k device running back to back with a 10 Gigabit Ethernet Controller device. Both systems are running a 4.1.1 kernel. The kernel should not be important as long as it is a fairly recent one that supports VXLAN.

When fm10k is loaded net devices will be created. On my system the fm10k device netdev is named 'p6p1'. For the purpose of clarity, I renamed it to 'p6p1-host1'.


```
# ip link set dev p6p1 name p6p1-host1
```


```
# ethtool -i p6p1-host1
driver: fm10k
version: 0.15.2
firmware-version:
bus-info: 0000:03:00.0
supports-statistics: yes
supports-test: yes
supports-eeprom-access: no
supports-register-dump: yes
supports-priv-flags: yes
```

On the other host I use a 10 Gigabit Ethernet Controller device and the 'p6p1' net device. Renaming 'p6p1' to 'p6p1-host2'.

```
# ip link set dev p6p1 name p6p1-host2
```


```
# ethtool -i p6p1-host2
driver: ixgbe
version: 4.0.1-k
firmware-version: 0x18bf0001
bus-info: 0000:02:00.0
supports-statistics: yes
supports-test: yes
supports-eeprom-access: yes
supports-register-dump: yes
supports-priv-flags: no
```

```
# ip link show dev p6p1-host2
8: p6p1-host2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 00:1b:21:69:9f:08 brd ff:ff:ff:ff:ff:ff
```

At this point another sanity check is usually worthwhile, so I assign IP addresses and attempt a ping,

```
# ping 60.0.0.1
PING 60.0.0.1 (60.0.0.1) 56(84) bytes of data.
64 bytes from 60.0.0.1: icmp_seq=1 ttl=64 time=0.706 ms
64 bytes from 60.0.0.1: icmp_seq=2 ttl=64 time=0.154 ms
```

Here I use IP address 60.0.0.1 and 60.0.0.2 for the two hosts.


Going forward I refer to the fm10k system as `Host 1` and the 10 Gigabit Ethernet Controller system as `Host 2`. Host1 is using IP address 60.0.0.1 and Host2 is using 60.0.0.2.


## Setup Software VXLAN

The next step is to get a basic software VXLAN setup running on both hosts.

##### Host 1

```
# ip link add vxlan0 type vxlan id 100 group 239.1.1.1 dev p6p1-host1 dstport 4789

# ip link add type bridge
# ip link set dev vxlan0 master bridge0

# ip netns add ns0

# ip link add type veth
# ip link set dev veth0 master bridge0
# ip link set dev veth1 netns ns0

# ip netns exec ns0 ifconfig veth1 70.0.0.22

# ip link set dev veth0 up
# ip link set dev bridge0 up
# ip link set dev vxlan0 up
```

Then mirror the setup on Host2 changing IP addresses and dev names,

##### Host 2

```
# ip link add vxlan0 type vxlan id 100 group 239.1.1.1 dev p6p1-host2 dstport 4789

# ip link add type bridge
# ip link set dev vxlan0 master bridge0

# ip netns add ns0

# ip link add type veth
# ip link set dev veth0 master bridge0
# ip link set dev veth1 netns ns0

# ip netns exec ns0 ifconfig veth1 70.0.0.21

# ip link set dev veth0 up
# ip link set dev bridge0 up
# ip link set dev vxlan0 up
```

Figure 1 shows the software test setup.


![Alt text](https://github.com/match-interface/match/blob/master/doc/tutorial/vxlan/img1.png "Figure 1: Software VXLAN Test Setup")


At this point the software VXLAN should be up and running. Using ping to test,

##### Host 1

```
# ip netns exec ns0 ping 70.0.0.21
PING 70.0.0.21 (70.0.0.21) 56(84) bytes of data.
64 bytes from 70.0.0.21: icmp_seq=1 ttl=64 time=0.360 ms
64 bytes from 70.0.0.21: icmp_seq=2 ttl=64 time=0.308 ms
64 bytes from 70.0.0.21: icmp_seq=3 ttl=64 time=0.298 ms
64 bytes from 70.0.0.21: icmp_seq=4 ttl=64 time=0.294 ms
```

It is useful to have a packet capturing tool running on both systems now so we can inspect traffic to verify the tunnels are in fact running.

Here two captures are shown one on the underlay and one on the overlay. Both the encapsulated frames and payload can be seen.

##### Host 2

```
# tshark -i p6p1-host2
Running as user "root" and group "root". This could be dangerous.
Capturing on p6p1-host2
  0.000000 abc_69:9f:08 -> xyz_23:45:6c ARP 42 Who has 60.0.0.2?  Tell 60.0.0.1
  0.000067 xyz_23:45:6c -> abc_69:9f:08 ARP 60 60.0.0.2 is at 00:a0:c9:23:45:6c
  0.004182     60.0.0.2 -> 60.0.0.1     UDP 148 Source port: 56590  Destination port: vxlan
  0.004325     60.0.0.1 -> 60.0.0.2     UDP 148 Source port: 37941  Destination port: vxlan

# tshark -i vxlan0
Running as user "root" and group "root". This could be dangerous.
Capturing on vxlan0
  0.000000    70.0.0.22 -> 70.0.0.21    ICMP 98 Echo (ping) request  id=0x3a08, seq=149/38144, ttl=64
  0.000074    70.0.0.21 -> 70.0.0.22    ICMP 98 Echo (ping) reply    id=0x3a08, seq=149/38144, ttl=64
```

## Setup Hardware VXLAN

First we need to provision the hardware with a table 'tcam-to-te' that will be used to steer traffic to encap and decap units. 'te' here stands for tunnel engine. As well as two additional tables to do the encapsulation and decapsulation of the VXLAN headers. These tables are labeled 'te-vxlan-encap' and 'te-vxlan-decap'.

##### Host 1

```
# match create source 1 name tcam-to-te id 20 size 64 match ethernet.dst_mac mask match ethernet.src_mac mask match ipv4.dst_ip mask match ipv4.src_ip mask match udp.dst_port mask action count action forward_to_tunnel_engine_A

# match create source 2 name te-vxlan-encap id 30 size 64 match ethernet.dst_mac exact action count action tunnel_encap

# match create source 2 name te-vxlan-decap id 31 size 64 match vxlan.vni exact action count action tunnel_decap
```

The match fields could be more or less specific, for this example, we use the ethernet dst_mac and then the VNI in decap. For a real world example both dst_mac and VNI are likely needed.


##### Host 1

```
# match get_tables
[...]
tcam-to-te:20 src 1 apply 0 size 64
  matches:
         field: ethernet [dst_mac src_mac]
         field: ipv4 [dst_ip src_ip]
         field: udp [dst_port]
  actions:
           16: count (  )
           19: forward_to_tunnel_engine_A ( u16 sub-table )
  attributes:

te-vxlan-encap:30 src 2 apply 0 size 64
  matches:
         field: ethernet [dst_mac (exact)]
  actions:
           16: count (  )
           17: tunnel_encap ( u32 dst_ip, u32 src_ip, u32 vni, u16 src_port, u16 dst_port )
  attributes:

te-vxlan-decap:31 src 2 apply 0 size 64
  matches:
         field: vxlan [vni (exact)]
  actions:
           16: count (  )
           18: tunnel_decap (  )
  attributes:
```


The get_tables command lists all the tables exported by the hardware device. The three provisioned tables are now listed.

First, let us setup the decap rules,

##### Host 1

```
# match set_rule prio 10 handle 1 table 31 match vxlan.vni 100 0xffffff action count action tunnel_decap

# match set_rule prio 10 handle 5 table 20 match ipv4.dst_ip 239.1.1.1 255.255.255.255 action count action forward_to_tunnel_engine_A 31

# match set_rule prio 10 handle 4 table 20 match ipv4.dst_ip 60.0.0.1 255.255.255.255 action count action forward_to_tunnel_engine_A 31
```

And then setup the encap rules,

##### Host 1

```
# match set_rule prio 10 handle 1 table 30 match ethernet.dst_mac c6:0e:85:bc:f8:09 ff:ff:ff:ff:ff:ff action count action tunnel_encap 60.0.0.2 60.0.0.1 100 0 4789
```


The above rule sets ethernet.dst_mac to the MAC address of the veth1 interface on Host 2.

```
# match set_rule prio 10 handle 2 table 30 match ethernet.dst_mac ff:ff:ff:ff:ff:ff ff:ff:ff:ff:ff:ff action count action tunnel_encap 60.0.0.2 60.0.0.1 100 0 4789
```

```
# match set_rule prio 10 handle 1 table 20 match ethernet.dst_mac c6:0e:85:bc:f8:09 ff:ff:ff:ff:ff:ff action count action forward_to_tunnel_engine_A 30
```

The above rule sets ethernet.dst_mac to the MAC address of the veth1 interface on Host 2.

```
# match set_rule prio 10 handle 2 table 20 match ethernet.src_mac 36:00:af:74:69:1a ff:ff:ff:ff:ff:ff match ethernet.dst_mac ff:ff:ff:ff:ff:ff ff:ff:ff:ff:ff:ff action count action forward_to_tunnel_engine_A 30
```


The above rule sets ethernet.src_mac to the MAC address of the veth1 interface on Host 1.

Now the hardware is doing the decap operation. If we tried a ping now it would fail because vxlan0 device is expecting encapsulated packets. So now we need to reconfigure the host to let hardware to the decap work.

##### Host 1

```
# ip link del dev vxlan0
# ip link set dev p6p1-host1 master bridge0
```

Figure 2 shows the first step in the hardware VXLAN setup.

![Alt text](https://github.com/match-interface/match/blob/master/doc/tutorial/vxlan/img2.png "Figure 2: Hardware VXLAN Test Setup (Step 1)")



We need to setup the correct destination MAC for the encapsulated packets. This is handled using a table attribute. Typically this would be setup by a controller or ARP resolution in the operating system. Here we do the lookup manually by running 'ip link'.


##### Host 2

```
# ip link show dev p6p1-host2
8: p6p1-host2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 00:1b:21:69:9f:08 brd ff:ff:ff:ff:ff:ff
```


##### Host 1

```
# match update id 2 attrib vxlan_dst_mac 00:1b:21:69:9f:08
```

Finally, since we reconfigured Host 1 we need to set the IP address of bridge0 to the IP address of p6p1-host1 (60.0.0.1), so that the ARP requests from Host 2 are not dropped. This is shown in Figure 3.

##### Host 1

```
# ifconfig p6p1-host1 0
# ifconfig bridge0 60.0.0.1
```


![Alt text](https://github.com/match-interface/match/blob/master/doc/tutorial/vxlan/img3.png "Figure 3: Hardware VXLAN Test Setup (Step 2)")


## Offloaded Ping :)

Now it is all setup and ready to run, we can ping and see offloaded VXLAN encap/decap working. To do this I issue a ping from namespace ns0,

##### Host 1

```
# ip netns exec ns0 ping 70.0.0.21
PING 70.0.0.21 (70.0.0.21) 56(84) bytes of data.
64 bytes from 70.0.0.21: icmp_seq=1 ttl=64 time=0.328 ms
64 bytes from 70.0.0.21: icmp_seq=2 ttl=64 time=0.299 ms
...
```

Clearly, ping is working. Now let us check hardware rules that are being used,

##### Host 1

```
# match get_rules table 20
table : 20  uid : 1  prio : 10  bytes : 25536  packets : 366
         ethernet.dst_mac = c6:0e:85:bc:f8:09 (ff:ff:ff:ff:ff:ff)
           16: count (  )
           19: forward_to_tunnel_engine_A ( u16 sub-table 30 )
table : 20  uid : 2  prio : 10  bytes : 10848  packets : 100
         ethernet.src_mac = 36:00:af:74:69:1a (ff:ff:ff:ff:ff:ff)
         ethernet.dst_mac = ff:ff:ff:ff:ff:ff (ff:ff:ff:ff:ff:ff)
           16: count (  )
           19: forward_to_tunnel_engine_A ( u16 sub-table 30 )
table : 20  uid : 4  prio : 10  bytes : 22968  packets : 157
         ipv4.dst_ip = 0100003c (ffffffff)
           16: count (  )
           19: forward_to_tunnel_engine_A ( u16 sub-table 31 )
table : 20  uid : 5  prio : 10  bytes : 12384  packets : 129
         ipv4.dst_ip = 010101ef (ffffffff)
           16: count (  )
           19: forward_to_tunnel_engine_A ( u16 sub-table 31 )

# match get_rules table 30
table : 30  uid : 1  prio : 10  bytes : 15848  packets : 100
         ethernet.dst_mac = c6:0e:85:bc:f8:09 (ff:ff:ff:ff:ff:ff)
           16: count (  )
           17: tunnel_encap ( u32 dst_ip 0x200003c, u32 src_ip 0x100003c, u32 vni 0x64, u16 src_port 0, u16 dst_port 4789 )
table : 30  uid : 2  prio : 10  bytes : 41724  packets : 342
         ethernet.dst_mac = ff:ff:ff:ff:ff:ff (ff:ff:ff:ff:ff:ff)
           16: count (  )
           17: tunnel_encap ( u32 dst_ip 0x200003c, u32 src_ip 0x100003c, u32 vni 0x64, u16 src_port 0, u16 dst_port 4789 )

# match get_rules table 31
table : 31  uid : 1  prio : 10  bytes : 23340  packets : 286
         vxlan.vni = 00000064 (00ffffff)
           16: count (  )
           18: tunnel_decap (  )
```


The important indicator above is the byte and packet counts. If we were to run a 'watch' command on the above commands we would see the packet counts incrementing.

Finally, running packet capturing tool on Host 2 shows vxlan encapsulated packets being received,

##### Host 2

```
# tshark -i p6p1-host2
Running as user "root" and group "root". This could be dangerous.
Capturing on p6p1-host2
  0.000000     60.0.0.1 -> 60.0.0.2     UDP 148 Source port: 0  Destination port: vxlan
  0.000176     60.0.0.2 -> 60.0.0.1     UDP 148 Source port: 37941  Destination port: vxlan
  0.998980     60.0.0.1 -> 60.0.0.2     UDP 148 Source port: 0  Destination port: vxlan
  0.999104     60.0.0.2 -> 60.0.0.1     UDP 148 Source port: 37941  Destination port: vxlan
```

That should be enough to convince the reader the hardware is in fact doing the encapsulation and decapsulation. And this completes the demo. Thanks.



## Reference
https://www.kernel.org/doc/Documentation/networking/vxlan.txt


## Scripts

##### Software VXLAN Setup – Host 1

```
#ip link add vxlan0 type vxlan id 100 group 239.1.1.1 dev p6p1-host1 dstport 4789

#ip link add type bridge
#ip link set dev vxlan0 master bridge0

#ip netns add ns0

#ip link add type veth
#ip link set dev veth0 master bridge0
#ip link set dev veth1 netns ns0

#ip netns exec ns0 ifconfig veth1 70.0.0.22

#ip link set dev veth0 up
#ip link set dev bridge0 up
#ip link set dev vxlan0 up
```

##### Software VXLAN Setup – Host 2

```
#ip link add vxlan0 type vxlan id 100 group 239.1.1.1 dev p6p1-host2 dstport 4789

#ip link add type bridge
#ip link set dev vxlan0 master bridge0

#ip netns add ns0

#ip link add type veth
#ip link set dev veth0 master bridge0
#ip link set dev veth1 netns ns0

#ip netns exec ns0 ifconfig veth1 70.0.0.22

#ip link set dev veth0 up
#ip link set dev bridge0 up
#ip link set dev vxlan0 up
```


##### Hardware VXLAN Setup – create tables – Host 1

```
# match create source 1 name tcam-to-te id 20 size 64 match ethernet.dst_mac mask match ethernet.src_mac mask match ipv4.dst_ip mask match ipv4.src_ip mask match udp.dst_port mask action count action forward_to_tunnel_engine_A

# match create source 2 name te-vxlan-encap id 30 size 64 match ethernet.dst_mac exact action count action tunnel_encap

# match create source 2 name te-vxlan-decap id 31 size 64 match vxlan.vni exact action count action tunnel_decap
```


##### Hardware VXLAN Setup – decap rules – Host 1

```
# match set_rule prio 10 handle 1 table 31 match vxlan.vni 100 0xffffff action count action tunnel_decap

# match set_rule prio 10 handle 5 table 20 match ipv4.dst_ip 239.1.1.1 255.255.255.255 action count action forward_to_tunnel_engine_A 31

# match set_rule prio 10 handle 4 table 20 match ipv4.dst_ip 60.0.0.1 255.255.255.255 action count action forward_to_tunnel_engine_A 31
```



##### Hardware VXLAN Setup – encap rules – Host 1

```
# match set_rule prio 10 handle 1 table 30 match ethernet.dst_mac c6:0e:85:bc:f8:09 ff:ff:ff:ff:ff:ff action count action tunnel_encap 60.0.0.2 60.0.0.1 100 0 4789

# match set_rule prio 10 handle 2 table 30 match ethernet.dst_mac ff:ff:ff:ff:ff:ff ff:ff:ff:ff:ff:ff action count action tunnel_encap 60.0.0.2 60.0.0.1 100 0 4789

# match set_rule prio 10 handle 1 table 20 match ethernet.dst_mac c6:0e:85:bc:f8:09 ff:ff:ff:ff:ff:ff action count action forward_to_tunnel_engine_A 30

# match set_rule prio 10 handle 2 table 20 match ethernet.src_mac 36:00:af:74:69:1a ff:ff:ff:ff:ff:ff match ethernet.dst_mac ff:ff:ff:ff:ff:ff ff:ff:ff:ff:ff:ff action count action forward_to_tunnel_engine_A 30
```


##### Hardware VXLAN Setup – reconfigure host & set destination MAC for encap packets – Host 1

```
# ip link del dev vxlan0
# ip link set dev p6p1-host1 master bridge0

# match update id 2 attrib vxlan_dst_mac 00:1b:21:69:9f:08

# ifconfig p6p1-host1 0
# ifconfig bridge0 60.0.0.1
```
