package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/canopy-network/go-plugin/contract"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// start the plugin and capture the running instance
	plugin := contract.StartPlugin(contract.DefaultConfig())
	// start the plugin's own HTTP server exposing custom, chain-specific RPC endpoints
	go plugin.StartRPCServer(ctx)
	<-ctx.Done()
}
