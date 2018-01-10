# -*- Mode: makefile-gmake -*-

SRC = \
	test-sailfish-connman-plugin-iptables.c \
	../src/sailfish-iptables-validate.c \
	../src/sailfish-iptables-parameters.c \
	../src/sailfish-iptables-utils.c \
	../src/sailfish-iptables-policy.c

NAME = plugin_unit_test

#
# Tools and flags
#

CC = $(CROSS_COMPILE)gcc
LD = $(CC)
WARNINGS = -Wall
BASE_FLAGS = -fPIC

ADD_CFLAGS=`pkg-config --cflags glib-2.0 dbus-1 libdbusaccess libglibutil`
ADD_LDFLAGS=`pkg-config --libs glib-2.0 dbus-1 libdbusaccess libglibutil`

FULL_CFLAGS = $(BASE_FLAGS) $(CFLAGS) $(ADD_CFLAGS) $(DEFINES) $(WARNINGS) -MMD -MP
FULL_LDFLAGS = $(BASE_FLAGS) $(LDFLAGS) $(ADD_LDFLAGS)

RELEASE_FLAGS = -g

RELEASE_LDFLAGS = $(FULL_LDFLAGS) $(RELEASE_FLAGS)
RELEASE_CFLAGS = $(FULL_CFLAGS) $(RELEASE_FLAGS) -O2

#
# Files
#

RELEASE_OBJS = $(SRC:%.c=%.o)

#
# Dependencies
#

DEPS = $(RELEASE_OBJS:%.o=%.d)
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(DEPS)),)
-include $(DEPS)
endif
endif

.PHONY: clean all debug release

all: test

build: $(NAME)

test: $(NAME) run

run:
	gtester $(NAME)

clean:
	$(RM) -f *~ $/*~
	$(RM) *.d *.o
	$(RM) $(NAME)

%.o : %.c
	$(CC) -c $(RELEASE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(NAME): $(RELEASE_OBJS)
	$(LD) $(RELEASE_OBJS) $(RELEASE_LDFLAGS) -o $@

