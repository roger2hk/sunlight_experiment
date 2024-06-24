package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"

	"myproj/client"

	"github.com/transparency-dev/merkle/rfc6962"
)

var (
	printTile = flag.Bool("print_tile", true, "whether to print the tile")
	logURL    = flag.String("log_url", "https://twig.ct.letsencrypt.org/2024h1", "log url without trailing slash")
)

func main() {
	ctx := context.Background()
	httpClient := &http.Client{}
	cpt, err := client.FetchCheckpoint(httpClient, *logURL)
	if err != nil {
		panic(err)
	}
	fmt.Printf("checkpoint size: %d\n", cpt.Size)
	c := client.NewCache(httpClient, *logURL, cpt.Size)

	// Check that tile 0, 0 is consistent with tiles 1, 0
	tile00, err := c.GetTile(ctx, 0, 0)
	if err != nil {
		panic(err)
	}
	want, err := c.GetHash(ctx, 8, 0)
	if err != nil {
		panic(err)
	}
	l := tile00.Nodes[7][0]
	r := tile00.Nodes[7][1]
	p := rfc6962.DefaultHasher.HashChildren(l[:], r[:])
	fmt.Printf("node at level 8, index 0 as computed by tile(0, 0)\n%v\n", p[:10])
	fmt.Printf("node at level 8, index 0 as fetched in tile(1, 0)\n%v\n", want[:10])
}
