DEV=enp6s18

all: up

up:
	sudo python3 -E tcserve.py $(DEV)

down:
	sudo tc qdisc del dev $(DEV) parent ffff:

status:
	sudo tc -s qdisc show dev $(DEV)

watch:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
