# Introduction

The Match interface is used to configure and populate match-action
tables in a packet processing pipeline.  Applications use the Match
interface API in conjunction with the Match daemon to configure the
tables and ports in the pipeline.

# Quick Start

Refer to the instructions in the [installation guide](https://github.com/match-interface/match/blob/master/INSTALL.md)
to quickly start using the Match interface.

# Software Overview

The Match interface software consists primarily of two components.

* The [Match Command Line Interface (CLI)](#cli)
* The [Match Daemon](#daemon)

### <a name="cli"></a>Match Command Line Interface (CLI)

The Match CLI accepts commands like *get_tables*, *get_headers*, etc. to
display information about the tables, headers, matches, rules, and ports
in a pipeline.

The CLI will pack the command into a netlink message and send it to the
[Match Daemon](#daemon) to execute.

For more information about the supported commands, users should consult
the Match CLI man page.

```
man match
```

Or for specific commands.

```
man match set_rule
```

### <a name="daemon"></a>Match Daemon

The Match Daemon will initialize the underlying packet processing pipeline
and wait for commands from Match interface applications, such as the
[Match CLI](#cli).

The daemon is designed to be installed as a systemd service that starts
when the system boots.
