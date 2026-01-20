BINARY=collector
SERVICE=collector.service
BPF_OBJ=bpf/sia_bpfel.o
LIBDIR=/var/lib/collector
BPFDEST=$(LIBDIR)/bpf
ENVFILE=/etc/collector.env

all: build

build:
	go build -o $(BINARY) .

install: build
	# Install binary + service
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)
	install -m 0644 $(SERVICE) /etc/systemd/system/$(SERVICE)

	# Create data directories
	mkdir -p $(BPFDEST)

	# Copy BPF object
	install -m 0644 $(BPF_OBJ) $(BPFDEST)/sia_bpfel.o

	# Create default env file if missing
	if [ ! -f $(ENVFILE) ]; then \
		echo 'SIA_HOSTNAME=""' > $(ENVFILE); \
				echo 'INTERFACE="eth0"' >> $(ENVFILE); \
		echo 'SQLITE_PATH="/var/lib/collector/traffic.db"' >> $(ENVFILE); \
		chmod 0644 $(ENVFILE); \
	fi

	# Reload systemd + enable service
	systemctl daemon-reload
	systemctl enable $(SERVICE)
	systemctl restart $(SERVICE)

uninstall:
	systemctl stop $(SERVICE)
	systemctl disable $(SERVICE)
	rm -f /usr/local/bin/$(BINARY)
	rm -f /etc/systemd/system/$(SERVICE)
	rm -rf $(LIBDIR)
	systemctl daemon-reload
