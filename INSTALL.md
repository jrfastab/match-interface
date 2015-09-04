# Installation Guide

The Match interface currently requires the following three components
to be installed.

* Intel(R) Ethernet Switch (IES) Host Interface Driver [link](http://sourceforge.net/projects/e1000/files/unsupported/fm10k%20unsupported/)
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
wget http://sourceforge.net/projects/e1000/files/unsupported/fm10k%20unsupported/fm10k-next_0.18.1.tar.gz/download -O fm10k-next_0.18.1.tar.gz
tar -xzf fm10k-next_0.18.1.tar.gz
cd fm10k-next_0.18.1/src
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

### Changing platform configuration files

By default, the configuration file for the sdi_adapter_100g_br network
adapter is used.  If a different network adapter is used the default
configuration file must be changed.

To change the default to the sdi_adapter_25g_ac configuration file, follow
the steps below.

```
cd /etc/ies/platforms/
rm -f default
ln -sf sdi_adapter_25g_ac default
systemctl start matchd.service
```

### Startup errors

When using the sdv_100g_rr network adapter, the following line must
be added to the sdv_100g_rr/fm_platform_attributes.cfg file.

```
api.platform.config.switch.0.uioDevName text /dev/uio0
```
