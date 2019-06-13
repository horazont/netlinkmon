CFLAGS += $(shell pkg-config --cflags libmnl) -Wall -Wextra -Werror
LDFLAGS += $(shell pkg-config --libs libmnl)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

netlinkmon: netlinkmon.o
	$(CC) $(LDFLAGS) $< -o $@
