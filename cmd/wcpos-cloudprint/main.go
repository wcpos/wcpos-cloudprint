package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
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
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	rl := &relay.Relay{
		Cfg:      cfg,
		Store:    store,
		State:    relay.NewPollState(),
		Health:   relay.NewOriginHealth(),
		Origin:   relay.NewOriginClient(20 * time.Second),
		RegLim:   relay.NewLimiter(1.0/600, 5), // 5-burst per IP, ~1 per 10 min refill
		FwdLim:   relay.NewLimiter(5, 10),      // origin forwards per site
		FetchLim: relay.NewLimiter(10, 20),     // payload fetches/results per site
		Now:      time.Now,
	}

	// Localhost-only plain-HTTP health endpoint for host-side monitoring.
	healthSrv := &http.Server{
		Addr:              cfg.HealthAddr,
		Handler:           rl.HealthHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       65 * time.Second,
	}
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("health server: %v", err)
		}
	}()

	var currentCert atomic.Value
	currentCert.Store(&cert)
	tlsConfig := relay.TLSConfig()
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return currentCert.Load().(*tls.Certificate), nil
	}
	stopReload := make(chan struct{})
	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				next, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
				if err != nil {
					log.Printf("certificate reload: %v", err)
					continue
				}
				currentCert.Store(&next)
			case <-stopReload:
				return
			}
		}
	}()

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           rl.Handler(),
		TLSConfig:         tlsConfig,
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
		close(stopReload)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("server shutdown: %v", err)
		}
		if err := healthSrv.Shutdown(ctx); err != nil {
			log.Printf("health server shutdown: %v", err)
		}
	}()
	log.Printf("wcpos-cloudprint listening on %s (mode=%s)", cfg.ListenAddr, cfg.Mode)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-shutdownDone
}
