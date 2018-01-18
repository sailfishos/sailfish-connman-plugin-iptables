# sailfish-connman-plugin-iptables

Connman plugin that provides D-Bus API for controlling iptables rules.

## API description

The detailed API description is provided as D-Bus introspect XML file (in
spec/sailfish_iptables_dbus_interface_description.xml) from which a docbook XML
is generated for the docs-package (run make -C doc). 

File contains descriptions for all the methods and parameters for each method.

### Generating documentation HTML

A html page can be generated from the introspect XML with the script at doc/docbook_html. The script requires xsltproc, docbook, docbook-xsl, docbook-xsl-ns, and docbook5-xml in order to generate the file from docbook XML.

## Loading the plugin

Plugin is loaded by Connection Manager at startup.

When loaded plugin registers its interface "org.sailfishos.connman.mdm.iptables"
under "net.connman" with path "/org/sailfishos/connman/mdm/iptables". Plugin
uses Connection Manager D-Bus functions to register itself to D-Bus.

After the plugin is loaded signal "Initialize" is sent over D-Bus indicating
that the plugin is running. Then iptables filter table content is loaded from
the default save path of connman iptables module for IPv4 rules. All previously
created custom chains (prefixed with sfos_) are loaded at plugin startup (using
iptables content returned by connman) into plugin's internal database.

When unloaded (by Connman at exit) iptables filter table is saved to connman's
default save path, iptables content is cleared, custom chains are removed from
the filter table and finally signal "Shutdown" is sent over D-Bus. Custom chains
are saved by connman's sailfish iptables extension.

## Plugin iptables operations

This plugin allows to:
 - Add a rule to iptables filter table
 - Remove a rule from iptables filter table
 - Change policy of a filter table chain INPUT and OUTPUT
 - Add a custom chain to filter table
 - Clear iptables rules
 - Clear iptables custom chains
 - Get iptables filter table content
 - Get version of plugin interface
 - Register (and unregister) to listen for API change signals
 

Rules can be added to any chains found iptables filter table. Each rule
can be added with any iptables target: ACCEPT, DENY, REJECT, QUEUE, LOG and
custom chains can be used as targets too. Custom chains must be used with the
name they are added, e.g., adding chain CUSTOM1 is added as sfos_CUSTOM1 and it
has to be used without the prefix "sfos_" as CUSTOM1.

Following parameters are supported:
 - Ip address or network 
 - Ip address or network with port
 - Ip address or network with port range
 - Ip address or network with service name
 - Port with any address 0.0.0.0
 - Port range with any address 0.0.0.0
 - Service name with any address 0.0.0.0
 
Both source and destination parameters are supported for all. Either or both
parameters (source or destination) must be set. They are added to iptables
accordingly.
 
For more information refer to xml documentation of the D-Bus interface of this
plugin (sailfish_iptables_dbus_interface_description.xml).

## Plugin D-Bus interface access

Access control prevents regular users from changing iptables content or to
listen for signals emitted by API. Default configuration is provided by the
installation and installed to /etc/connman/iptables_policy.conf. Configuration
is loaded from this file, which follows libdbusaccess policy format (see 
https://git.merproject.org/mer-core/libdbusaccess/).

If a client wishes to get the signals (detailed later) client has to call
method Register() successfully. Method use does not require use of Register()
method. On each function call (except GetVersion()) the access is checked
from D-Bus access policy (via libdbusaccess).

Three different properties are supported in the policy configuration file:
full, manage and listen.

### full()

Allow everything, no restrictions on access. All signals can be received.

### manage()

Make changes to iptables content (add/remove rules and custom chains). Clearing
of iptables table with ClearIptablesTable() method is not allowed. All signals
can be received.

### listen()

Can only listen for D-Bus signals emitted by API after calling method Register().

## Signals

The API emits following signals (further described in the D-Bus introspect XML/
HTML documentation):

### Initialize

Plugin is initialized and ready to be used.

Signal is sent to all.

### Shutdown

Plugin is unloaded.

Signal is sent to all.

### IptablesTableCleared

Iptables table has been cleared from all rules. Table name as string parameter.

Signal is sent to clients with at least listen() access.

### IptablesChainsCleared

Iptables table has been cleared from all custom chains. Table name as string
parameter.

Signal is sent to clients with at least listen() access.

### PolicyChanged

Iptables chain policy has been changed. Signal contains table and chain names
as strings as well as the new policy.

Signal is sent to clients with at least listen() access.

### RuleChanged

A rule has been changed (add or remove) in iptables. Ip address, port/port
range, protocol and operation (ADD/REMOVE) are sent as string parameters.

Signal is sent to clients with at least listen() access.

### ChainChanged

A chain was added or removed in a table. Affected table and chain are sent as
string parameter with operation type (ADD/REMOVE).

Signal is sent to clients with at least listen() access.

## Example of use

The following examples use command "dbus-send".

### Change input policy to disallow all connections

```
dbus-send --system \
--type=method_call \
--print-reply \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.ChangeInputPolicy \
string:"drop"
```

### Add rule to allow incoming connections from 192.168.0.1

```
dbus-send --system \
--type=method_call \
--print-reply \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.RuleIp \
string:filter string:INPUT string:ACCEPT \
string:192.168.0.1 string: uint16:0
```

### Add rule to deny outgoing connections to 192.168.0.2

```
dbus-send --system \
--type=method_call \
--print-reply \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.RuleIp \
string:filter string:OUTPUT string:DROP \
string: string:192.168.0.2 uint16:0
```

### Deny outgoing connections to tcp ports 8000 to 9000

```
dbus-send --system \
--type=method_call \
--print-reply \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.RulePortRange \
string:filter string:OUTPUT string:DROP \
uint16:8000 uint16:9000 uint16:0 uint16:0 \
uint32:6 uint16:0
```

### Deny incoming connections from udp ports 8000 to 9000

```
dbus-send --system \
--type=method_call \
--print-reply \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.RulePortRange \
string:filter string:INPUT string:DROP \
uint16:0 uint16:0 uint16:8000 uint16:9000 \
uint32:17 uint16:0
```

### Remove rule to drop connections from ssh service running on 192.168.0.2

```
dbus-send --system \
--type=method_call \
--print-reply \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.RuleIpWithService \
string:filter string:INPUT string:DROP \
string:192.168.0.2 string: string:ssh string: uint16:1
```

### Add a custom chain to filter table

```
dbus-send --system \
--type=method_call \
--print-reply \
--dest="net.connman" \
/org/sailfishos/connman/mdm/iptables \
org.sailfishos.connman.mdm.iptables.ManageChain \
string:filter string:CUSTOM1 uint16:0
```

### Result codes to method calls

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
|13 | "Invalid table name given." |
|14	| "Invalid target name given."|
|100 |"Access denied"|

In addition, GetIptablesContent will return two string arrays (if error these
are empty arrays):

| Return value | Description |
|--------------|-------------|
| array [ string ] | Chains in filter table in format "CHAINNAME CHAINPOLICY" |
| array [ string ] | Rules in filter table in raw iptables format |
