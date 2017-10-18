# -*- Mode: makefile-gmake -*-

.PHONY: clean all release

#
# Default target
#

all: debug release

#
# Library name
#
NAME = sailfish-iptables-api-plugin
LIB_NAME = $(NAME)
LIB_SONAME = $(LIB_NAME).so
LIB = $(LIB_SONAME)

#
# Sources
#
SRC = \
 sailfish-iptables-api.c \

#
# Directories
#

SRC_DIR = src
BUILD_DIR = build
DEBUG_BUILD_DIR = $(BUILD_DIR)/debug
RELEASE_BUILD_DIR = $(BUILD_DIR)/release

#
# Tools and flags
#

CC = $(CROSS_COMPILE)gcc
LD = $(CC)
WARNINGS = -Wall
BASE_FLAGS = -fPIC
FULL_CFLAGS = $(BASE_FLAGS) $(CFLAGS) $(DEFINES) $(WARNINGS) -MMD -MP
FULL_LDFLAGS = $(BASE_FLAGS) $(LDFLAGS) -shared -Wl,-soname -Wl,$(LIB_SONAME)
DEBUG_FLAGS = -g
RELEASE_FLAGS = -g

DEBUG_LDFLAGS = $(FULL_LDFLAGS) $(DEBUG_FLAGS)
RELEASE_LDFLAGS = $(FULL_LDFLAGS) $(RELEASE_FLAGS)
DEBUG_CFLAGS = $(FULL_CFLAGS) $(DEBUG_FLAGS) -DDEBUG
RELEASE_CFLAGS = $(FULL_CFLAGS) $(RELEASE_FLAGS) -O2

#
# Files
#

DEBUG_OBJS = $(SRC:%.c=$(DEBUG_BUILD_DIR)/%.o)
RELEASE_OBJS = $(SRC:%.c=$(RELEASE_BUILD_DIR)/%.o)

#
# Dependencies
#

DEPS = $(RELEASE_OBJS:%.o=%.d)
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(DEPS)),)
-include $(DEPS)
endif
endif

$(DEBUG_OBJS) $(DEBUG_LIB): | $(DEBUG_BUILD_DIR)
$(RELEASE_OBJS) $(RELEASE_LIB): | $(RELEASE_BUILD_DIR)

#
# Rules
#

DEBUG_LIB = $(DEBUG_BUILD_DIR)/$(LIB)
RELEASE_LIB = $(RELEASE_BUILD_DIR)/$(LIB)

debug: $(DEBUG_LIB)

release: $(RELEASE_LIB)

clean:
	rm -f *~ $(SRC_DIR)/*~
	rm -fr $(BUILD_DIR) RPMS installroot

$(DEBUG_BUILD_DIR):
	mkdir -p $@

$(RELEASE_BUILD_DIR):
	mkdir -p $@

$(DEBUG_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(DEBUG_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(RELEASE_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(RELEASE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(DEBUG_LIB): $(DEBUG_OBJS)
	$(LD) $(DEBUG_OBJS) $(DEBUG_LDFLAGS) -o $@

$(RELEASE_LIB): $(RELEASE_OBJS)
	$(LD) $(RELEASE_OBJS) $(RELEASE_LDFLAGS) -o $@

#
# Install
#

INSTALL_PERM  = 755
INSTALL_OWNER = $(shell id -u)
INSTALL_GROUP = $(shell id -g)
INSTALL = install
INSTALL_DIRS = $(INSTALL) -d
INSTALL_FILES = $(INSTALL) -m $(INSTALL_PERM)
INSTALL_LIB_DIR = $(DESTDIR)/usr/lib/connman/plugins

install: $(INSTALL_LIB_DIR)
	$(INSTALL_FILES) $(RELEASE_LIB) $(INSTALL_LIB_DIR)

$(INSTALL_LIB_DIR):
	$(INSTALL_DIRS) $@
