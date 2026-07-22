package main

import (
	"log"
	"net/http"
	"os"
	"time"

	relay "github.com/wcpos/wcpos-cloudprint"
)

func main() {
	cfg, err := relay.LoadConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	store, err := relay.OpenStore(cfg.SitesPath)
	if err != nil {
		log.Fatal(err)
	}
	rl := &relay.Relay{
		Cfg:    cfg,
		Store:  store,
		State:  relay.NewPollState(),
		Health: relay.NewOriginHealth(),
		Origin: relay.NewOriginClient(20 * time.Second),
		RegLim: relay.NewLimiter(1.0/600, 5), // 5-burst per IP, ~1 per 10 min refill
		FwdLim: relay.NewLimiter(5, 10),      // origin forwards per site
		Now:    time.Now,
	}

	// Localhost-only plain-HTTP health endpoint for host-side monitoring.
	go func() {
		log.Fatal(http.ListenAndServe(cfg.HealthAddr, rl.Handler()))
	}()

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           rl.Handler(),
		TLSConfig:         relay.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       65 * time.Second,
	}
	log.Printf("wcpos-cloudprint listening on %s (mode=%s)", cfg.ListenAddr, cfg.Mode)
	log.Fatal(srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile))
}
