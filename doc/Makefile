# -*- Mode: makefile-gmake -*-

.PHONY: clean docbook_xml

SPECFILE="../spec/sailfish_iptables_dbus_interface_description.xml"
DOCBOOK_PREFIX="generated-doc"
INTERFACE="org.sailfishos.connman.mdm.iptables"
DOCBOOK_XML="$(DOCBOOK_PREFIX)-$(INTERFACE).xml"

all: docbook_xml

docbook_xml:
	@gdbus-codegen --generate-docbook $(DOCBOOK_PREFIX) --interface-prefix=$(INTERFACE) $(SPECFILE)

clean:
	@$(RM) $(DOCBOOK_XML)
