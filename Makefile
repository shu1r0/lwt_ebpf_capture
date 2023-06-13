
.PHONY: test

CAPTURE_DIR="./cmd/lwt_capture/"

build:
	go mod tidy
	# go generate ./...
	cd $(CAPTURE_DIR);go build main.go;chmod +x main;cd -

test:
	sudo ./test/netns_network_examples/simple/2hosts_1router.sh -c
	# sudo ip netns exec r1 ./cmd/lwt_capture/main

clean:
	sudo ./test/netns_network_examples/simple/2hosts_1router.sh -d