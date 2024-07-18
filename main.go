package main

import (
	"context"
	"go-arp-attack/cmd"
	"log/slog"
	"os"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))

	if err := cmd.ParseFlags(context.Background()); err != nil {
		slog.Error("programme exit", slog.Any("error", err))
	}
}
