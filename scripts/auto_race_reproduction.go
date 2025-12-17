package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url" // Required for cookiejar initialization which uses URL parsing implicitly
	"os"
	"strings"
	"sync"
	"sync/atomic" // Used for thread-safe increment of counters
	"time"

	"github.com/joho/godotenv" // For loading environment variables from .env file
)

// Make sure .env contains the following variables:
// BASE_URL=http://localhost:8080
// TARGET_UID=your-uuid-here # A valid user UUID for login
// TARGET_SLUG=an-existing-organization-slug-that-can-be-updated # A slug that the TenantMiddleware should resolve

var (
	httpClient         *http.Client
	baseURL            string
	targetUID          string
	targetSlug         string
	reproducedCount    atomic.Int64 // Counter for successfully reproduced errors
	totalRequestsMade  atomic.Int64 // Counter for total HTTP requests made
)

// setup initializes the HTTP client with a cookie jar and performs a login.
// This ensures that subsequent requests by concurrent workers are authenticated.
func setup() {
	// Load environment variables from .env file.
	// This helps in setting up the test parameters without hardcoding them.
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: No .env file found or failed to load. Will attempt to use system environment variables. Error: %v", err)
	}

	// Retrieve necessary configuration from environment variables.
	baseURL = os.Getenv("BASE_URL")
	targetUID = os.Getenv("TARGET_UID")
	targetSlug = os.Getenv("TARGET_SLUG")

	// Validate critical environment variables.
	if baseURL == "" {
		log.Fatal("Error: BASE_URL environment variable not set. Please specify the base URL of the target server.")
	}
	if targetUID == "" {
		log.Fatal("Error: TARGET_UID environment variable not set. Please provide a valid UUID for authentication.")
	}
	if targetSlug == "" {
		log.Fatal("Error: TARGET_SLUG environment variable not set. This slug should correspond to an existing organization that the server's TenantMiddleware is expected to handle.")
	}

	// Initialize a cookie jar to manage session cookies automatically.
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalf("Failed to create cookie jar for HTTP client: %v", err)
	}

	// Configure the HTTP client with the cookie jar and a timeout.
	httpClient = &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second, // Set a reasonable timeout to prevent hanging requests.
	}

	// 1. Perform login to acquire session cookies.
	loginURL := fmt.Sprintf("%s/api/auth/login/internal", baseURL)
	loginPayload := map[string]string{"uid": targetUID}
	payloadBytes, err := json.Marshal(loginPayload)
	if err != nil {
		log.Fatalf("Failed to marshal login payload for user %s: %v", targetUID, err)
	}

	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Fatalf("Failed to create login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("Login request to %s failed: %v", loginURL, err)
	}
	defer resp.Body.Close() // Ensure response body is closed to prevent resource leaks.

	// Check login response status.
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read body for detailed error message
		log.Fatalf("Login failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	log.Printf("Login successful for UID '%s', authenticated client initialized.", targetUID)
}

// worker simulates concurrent PUT requests to the /api/orgs/{slug} endpoint.
// The `expert_analysis` indicates a race condition where the TenantMiddleware
// incorrectly resolves a valid slug to a nil UUID (00000000-0000-0000-0000-000000000000)
// under high concurrency, leading to "unable to find tenants with id '00000000-0000-0000-0000-000000000000'" errors.
func worker(workerID int, requestsPerWorker int, wg *sync.WaitGroup) {
	defer wg.Done() // Signal that this worker has completed its tasks.

	// The payload for the PUT request. The specific content might not be the root cause
	// of the nil UUID issue, but a valid JSON body is required for the request.
	putPayload := map[string]string{
		"name": fmt.Sprintf("Updated Org from Worker %d (Time: %s)", workerID, time.Now().Format("15:04:05")),
	}
	payloadBytes, err := json.Marshal(putPayload)
	if err != nil {
		log.Printf("Worker %d: Failed to marshal PUT payload: %v", workerID, err)
		return
	}

	targetURL := fmt.Sprintf("%s/api/orgs/%s", baseURL, targetSlug)

	// This is the specific error message fragment identified in the `primary_error_log`
	// and `expert_analysis` as indicating the nil UUID issue.
	errorFragment := "unable to find tenants with id '00000000-0000-0000-0000-000000000000'"

	for i := 0; i < requestsPerWorker; i++ {
		totalRequestsMade.Add(1) // Increment total requests counter atomically.

		req, err := http.NewRequest(http.MethodPut, targetURL, bytes.NewBuffer(payloadBytes))
		if err != nil {
			log.Printf("Worker %d, Request %d: Failed to create PUT request for %s: %v", workerID, i, targetURL, err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			log.Printf("Worker %d, Request %d: HTTP request to %s failed: %v", workerID, i, targetURL, err)
			continue
		}
		defer resp.Body.Close() // Close the response body for each request.

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Worker %d, Request %d: Failed to read response body from %s: %v", workerID, i, targetURL, err)
			continue
		}
		responseBody := string(bodyBytes)

		// Check if the response body contains the specific error fragment.
		// This is the core assertion step to confirm the reproduction of the nil UUID error.
		if strings.Contains(responseBody, errorFragment) {
			reproducedCount.Add(1) // Increment error reproduction counter atomically.
			log.Printf("Worker %d, Request %d: Error Reproduced Successfully! Target URL: %s, Response: %s", workerID, i, targetURL, responseBody)
			// Depending on the goal, one might choose to exit or continue after the first reproduction.
			// For load testing context, we continue to observe frequency.
		} else if resp.StatusCode != http.StatusOK {
			// Log other non-200 responses to provide broader context,
			// even if they don't match the specific error fragment.
			log.Printf("Worker %d, Request %d: Non-200 status %d for %s. Response: %s", workerID, i, resp.StatusCode, targetURL, responseBody)
		}
	}
}

func main() {
	// Initialize the HTTP client and authenticate the user.
	// This pre-condition is essential for making requests to protected API endpoints.
	setup()

	// Configuration for concurrency, driven by `analysis_mode: MODE_PERFORMANCE_CONCURRENCY`
	// and keywords like "k6", "load test", "concurrent".
	numWorkers := 20     // Number of concurrent goroutines (simulated users).
	requestsPerWorker := 100 // Number of requests each worker will make.

	var wg sync.WaitGroup // WaitGroup to wait for all goroutines to complete.
	log.Printf("Starting %d workers, each making %d requests to reproduce the concurrency issue on /api/orgs/%s...", numWorkers, requestsPerWorker, targetSlug)

	// Launch worker goroutines.
	for i := 1; i <= numWorkers; i++ {
		wg.Add(1)
		go worker(i, requestsPerWorker, &wg)
	}

	wg.Wait() // Wait until all worker goroutines have finished.

	// Retrieve final counts of reproduced errors and total requests.
	finalReproducedCount := reproducedCount.Load()
	finalTotalRequests := totalRequestsMade.Load()

	log.Println("\n--- Reproduction Summary ---")
	log.Printf("Total requests made: %d", finalTotalRequests)
	log.Printf("Errors of type 'unable to find tenants with id '00000000-0000-0000-0000-000000000000'' reproduced: %d", finalReproducedCount)

	// Provide a clear outcome based on whether the error was reproduced.
	if finalReproducedCount > 0 {
		log.Println("--------------------------------------------------------------------")
		log.Println("!!! CONCURRENCY ERROR (Nil UUID in TenantMiddleware) REPRODUCED SUCCESSFULLY !!!")
		log.Println("--------------------------------------------------------------------")
		os.Exit(0) // Exit with success code if the error was reproduced.
	} else {
		log.Println("--------------------------------------------------------------------")
		log.Println("Concurrency error not reproduced with the current settings.")
		log.Println("Consider increasing 'numWorkers' or 'requestsPerWorker', or verify 'TARGET_SLUG' is valid and causes the issue.")
		log.Println("--------------------------------------------------------------------")
		os.Exit(1) // Exit with error code if reproduction failed.
	}
}