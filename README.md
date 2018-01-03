# sailfish-connman-plugin-iptables

Connman plugin that provides D-Bus API for controlling iptables rules.

## Loading the plugin

Plugin is loaded by Connection Manager at startup.

When loaded plugin registers its interface "org.sailfishos.connman.mdm.iptables"
under "net.connman" with path "/org/sailfishos/connman/mdm/iptables". Plugin
uses Connection Manager D-Bus functions to register itself to D-Bus.

After the plugin is loaded signal "Initialize" is sent over D-Bus indicating
that the plugin is running. Then iptables filter table content is loaded from
the default save path of connman iptables module for IPv4 rules. All previously created custom chains (prefixed with sfos_) are loaded at plugin startup (using iptables content returned by connman) into plugin's internal database.'

When unloaded (by Connman at exit) iptables filter table is saved to connman's
default save path, iptables content is cleared, custom chains are removed from
the filter table and finally signal "Shutdown" is sent over D-Bus. Custom chains are saved by connman's sailfish iptables extension.

## Plugin iptables operations

This plugin allows to:
 - Add a rule to iptables filter table
 - Remove a rule from iptables filter table
 - Change policy of a filter table chain INPUT and OUTPUT
 - Add a chain to filter table
 - Save iptables to disk at shutdown using connman's sailfish iptables extension
 - Load iptables from disk at startup using connman's sailfish iptables extension
 - Clear iptables rules
 - Clear iptables custom chains
 - Get iptables filter table content
 - Get version of plugin interface

Rules can be added to INPUT or OUTPUT chains of iptables filter table. Each rule
can be added as ACCEPT or DENY.

Following parameters are supported:
 - Ip address or network
 - Ip address or network with port
 - Ip address or network with port range
 - Ip address or network with service name
 - Port with any address (0.0.0.0)
 - Port range with any address (0.0.0.0)
 - Service name with any address (0.0.0.0)
 
For more information refer to xml documentation of the D-Bus interface of this
plugin (sailfish_iptables_dbus_interface_description.xml).

## Plugin D-Bus interface access

WIP no access control is yet implemented.

## Example of use

The following examples use command "dbus-send".

### Change input policy to disallow all connections

```
dbus-send --system \
--type=method_call \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.ChangeInputPolicy \
string:"drop"
```

### Add rule to allow incoming connections from 192.168.0.1

```
dbus-send --system \
--type=method_call \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.AllowIncomingIp \
string:"192.168.0.1" string:"add"
```

### Deny outgoing connections to tcp ports 8000 to 9000

```
dbus-send --system \
--type=method_call \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.DenyOutgoingPortRange \
string:"8000:9000" string:"tcp" string:"add"
```

### Remove rule to drop connections from ssh service running on 192.168.0.2

```
dbus-send --system \
--type=method_call \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.DenyIncomingIpWithService \
string:"192.168.0.2" string:"ssh" string:"" string:"remove"
```

### Errors to method calls

Each method call results in a reply containing integer and corresponding
textual description as follows:

|Return value|Description|
|------------|-----------|
|0	|"Ok"|
|1	|"Invalid IP"|
|2	|"Invalid port"|
|3	|"Invalid port range"|
|4	|"Invalid service name"|
|5	|"Invalid protocol"|
|6	|"Invalid policy"|
|7	|"Rule does not exist"|
|8	|"Cannot process request"|
|9	|"Cannot perform operation"|
|10 |"Unauthorized, please try again"|
|11 |"Unregister failed"|
|12 |"Invalid chain name given. Chain name is reserved (add) or does not exist (remove)."|
|13 |"Access denied"|

In addition, GetIptablesContent will return two string arrays:

| Return value | Description |
|--------------|-------------|
| array [ string ] | Chains in filter table in format "CHAINNAME CHAINPOLICY" |
| array [ string ] | Rules in filter table in raw iptables format |
