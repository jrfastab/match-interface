# Installation Guide

The Match interface currently requires the following three components
to be installed.

* Intel(R) Ethernet Switch (IES) Host Interface Driver [link](TBD)
* Intel(R) Ethernet Switch (IES) Software [link](https://github.com/match-interface/IES)
* Match interface [link](https://github.com/match-interface/match)

If issues arise, please refer to the [troubleshooting](#troubleshooting)
section of this guide.

## Procedure

The following steps detail the procedure to install the components
required to run the Match command line tool and other applications
written to use the Match libraries and/or daemon.


### Install required packages

```
yum install wget git kernel-devel gcc autoconf automake \
            pkgconfig libtool libnl3-devel graphviz-devel
```

### Host Interface Driver

```
wget <TBD>.tar.gz
tar -xzf <TBD>.tar.gz
cd <TBD>/src
make
make install
cd ../..
rmmod fm10k
modprobe fm10k
```

### IES Software

```
git clone https://github.com/match-interface/IES.git IES
cd IES
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc
make
make install
cd ..
source /etc/profile.d/ies.sh
```

### Match Interface

```
git clone https://github.com/match-interface/match.git match
cd match
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc
make
make install
cd ..
```

### Enable and start the daemon

```
systemctl enable matchd.service
systemctl start matchd.service
```

# <a name="troubleshooting"></a>Troubleshooting

### View Log Messages

When installed as a systemd service, the Match daemon will emit log
messages to the systemd journal.  The following command is used
to display the messages.

```
journalctl --unit matchd
```

### Manage the service

When installed as a systemd service, the Match daemon can be started
and stopped using the following commands.

#### Starting the service

```
systemctl start matchd.service
```

#### Stopping the service

```
systemctl stop matchd.service
```
