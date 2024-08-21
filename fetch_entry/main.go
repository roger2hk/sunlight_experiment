package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"

	"myproj/client"
)

var (
	logURL  = flag.String("log_url", "https://rome2025h2.fly.storage.tigris.dev", "log url without trailing slash")
	logName = flag.String("log_name", "rome_2025h2", "")
)

func main() {
	ctx := context.Background()
	httpClient := &http.Client{}
	cpt, err := client.FetchCheckpoint(httpClient, *logURL)
	if err != nil {
		panic(err)
	}
	fmt.Printf("checkpoint size: %d\n", cpt.Size)
	c, err := client.NewClient(httpClient, *logURL, *logName)
	if err != nil {
		panic(err)
	}

	tile100, err := c.GetEntryTile(ctx, 100, uint64(cpt.Size))
	if err != nil {
		panic(err)
	}
	fmt.Println(tile100)

}
