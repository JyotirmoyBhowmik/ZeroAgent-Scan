package vulnscan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
)

// WorkerConfig holds configuration options for the VulnScan background worker.
type WorkerConfig struct {
	NVDAPIKey       string
	NVDBaseURL      string
	CISAKEVURL      string
	SyncInterval    time.Duration
	EnableAutoSync  bool
}

// VulnScanWorker manages scheduled ingestion of NVD CVE feed and CISA KEV catalog.
type VulnScanWorker struct {
	cfg        WorkerConfig
	nvdClient  *NVDClient
	kevClient  *KEVClient
	repo       FindingRepository
	scanEngine *ScanEngine
	stopChan   chan struct{}
	wg         sync.WaitGroup
	mu         sync.Mutex
	running    bool
	lastSyncAt time.Time
}

// NewVulnScanWorker creates a configured vulnerability scanner background worker.
func NewVulnScanWorker(cfg WorkerConfig, repo FindingRepository, nvdClient *NVDClient, kevClient *KEVClient) *VulnScanWorker {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 1 * time.Hour
	}

	if nvdClient == nil {
		nvdClient = NewNVDClient(cfg.NVDBaseURL, cfg.NVDAPIKey, nil)
	}
	if kevClient == nil {
		kevClient = NewKEVClient(cfg.CISAKEVURL, nil)
	}

	return &VulnScanWorker{
		cfg:        cfg,
		nvdClient:  nvdClient,
		kevClient:  kevClient,
		repo:       repo,
		scanEngine: NewScanEngine(repo),
		stopChan:   make(chan struct{}),
	}
}

// GetScanEngine returns the underlying scan engine for scanning host snapshots.
func (w *VulnScanWorker) GetScanEngine() *ScanEngine {
	return w.scanEngine
}

// GetRepository returns the findings and cache repository.
func (w *VulnScanWorker) GetRepository() FindingRepository {
	return w.repo
}

// Start launches the background synchronization loop.
func (w *VulnScanWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return fmt.Errorf("vulnscan_worker: worker is already running")
	}
	w.running = true
	w.stopChan = make(chan struct{})
	w.mu.Unlock()

	middleware.LogJSON("info", "vulnscan_worker", "vulnscan", "Starting VulnScan background worker daemon")

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()

		// Initial sync on boot
		if w.cfg.EnableAutoSync {
			syncCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			if err := w.SyncFeedsNow(syncCtx); err != nil {
				middleware.LogJSON("error", "vulnscan_worker", "vulnscan", fmt.Sprintf("Initial vulnerability feed sync failed: %v", err))
			}
			cancel()
		}

		ticker := time.NewTicker(w.cfg.SyncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-w.stopChan:
				middleware.LogJSON("info", "vulnscan_worker", "vulnscan", "VulnScan background worker stopped")
				return
			case <-ctx.Done():
				middleware.LogJSON("info", "vulnscan_worker", "vulnscan", "VulnScan background worker context cancelled")
				return
			case <-ticker.C:
				if w.cfg.EnableAutoSync {
					syncCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
					if err := w.SyncFeedsNow(syncCtx); err != nil {
						middleware.LogJSON("error", "vulnscan_worker", "vulnscan", fmt.Sprintf("Periodic vulnerability feed sync failed: %v", err))
					}
					cancel()
				}
			}
		}
	}()

	return nil
}

// Stop gracefully shuts down the background synchronization worker.
func (w *VulnScanWorker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	close(w.stopChan)
	w.mu.Unlock()

	w.wg.Wait()
}

// SyncFeedsNow ingests the CISA KEV catalog and NVD API 2.0 CVE feed immediately.
func (w *VulnScanWorker) SyncFeedsNow(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	middleware.LogJSON("info", "vulnscan_worker", "vulnscan", "Starting vulnerability feed sync (CISA KEV + NVD API 2.0)")

	// 1. Ingest CISA KEV Catalog
	_, kevMap, err := w.kevClient.FetchCatalog(ctx)
	if err != nil {
		return fmt.Errorf("vulnscan_worker: failed to fetch CISA KEV catalog: %w", err)
	}
	if err := w.repo.SaveKEVCatalog(kevMap); err != nil {
		return fmt.Errorf("vulnscan_worker: failed to save CISA KEV catalog: %w", err)
	}
	middleware.LogJSON("info", "vulnscan_worker", "vulnscan", fmt.Sprintf("Successfully ingested %d CISA KEV catalog entries", len(kevMap)))

	// 2. Ingest NVD API 2.0 Feed
	var lastModStart *time.Time
	if !w.lastSyncAt.IsZero() {
		t := w.lastSyncAt.Add(-24 * time.Hour) // 24-hour overlap window for safety
		lastModStart = &t
	}

	opts := FetchCVEsOptions{
		StartIndex:       0,
		ResultsPerPage:   200,
		LastModStartDate: lastModStart,
	}
	if lastModStart != nil {
		now := time.Now().UTC()
		opts.LastModEndDate = &now
	}

	nvdResp, err := w.nvdClient.FetchCVEPage(ctx, opts)
	if err != nil {
		return fmt.Errorf("vulnscan_worker: failed to query NVD API 2.0: %w", err)
	}

	var cachedItems []*CachedCVE
	for _, v := range nvdResp.Vulnerabilities {
		cached := ConvertNVDItemToCached(v.CVE)
		cachedItems = append(cachedItems, cached)
	}

	if err := w.repo.SaveCachedCVEs(cachedItems); err != nil {
		return fmt.Errorf("vulnscan_worker: failed to save cached CVEs: %w", err)
	}

	w.lastSyncAt = time.Now().UTC()
	middleware.LogJSON("info", "vulnscan_worker", "vulnscan", fmt.Sprintf("Successfully ingested %d CVEs from NVD API 2.0", len(cachedItems)))

	return nil
}
