package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	relay "github.com/wcpos/wcpos-cloudprint"
)

func main() {
	secret, err := relay.ParseMasterSecret(os.Getenv("RELAY_MASTER_SECRET"))
	if err != nil {
		log.Fatal(err)
	}
	store, err := relay.OpenStore(relay.SitesPath)
	if err != nil {
		log.Fatal(err)
	}
	rl := &relay.Relay{
		MasterSecret: secret,
		Store:        store,
		State:        relay.NewPollState(),
		Health:       relay.NewOriginHealth(),
		Origin:       relay.NewOriginClient(20 * time.Second),
		RegLim:       relay.NewLimiter(1.0/600, 5), // 5-burst per IP, ~1 per 10 min refill
		FwdLim:       relay.NewLimiter(5, 10),      // origin forwards per site
		FetchLim:     relay.NewLimiter(10, 20),     // payload fetches/results per site
		Now:          time.Now,
	}

	srv := &http.Server{
		Addr:              relay.ListenAddr,
		Handler:           relay.LogRequests(rl.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       65 * time.Second,
	}
	signals, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	shutdownDone := make(chan struct{})
	go func() {
		<-signals.Done()
		defer close(shutdownDone)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("server shutdown: %v", err)
		}
	}()
	log.Printf("wcpos-cloudprint listening on %s", relay.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-shutdownDone
}
