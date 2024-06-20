package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"

	"myproj/client"
)

var (
	treeLevel = flag.Int("tree_level", 24, "tree level")
	treeIndex = flag.Int("tree_index", 0, "tree index")
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
	h, err := c.GetHash(ctx, *treeLevel, *treeIndex)
	if err != nil {
		panic(err)
	}
	if *printTile {
		tileLevel, tileIndex, _, _ := client.TreeCoordsToTileNodeAddress(uint64(*treeLevel), uint64(*treeIndex))
		t, err := c.GetTile(ctx, int(tileLevel), int(tileIndex))
		if err != nil {
			panic(err)
		}
		for i := len(t.Nodes) - 1; i >= 0; i-- {
			for _, hs := range t.Nodes[i] {
				enc := base64.StdEncoding.EncodeToString(hs[:])
				fmt.Printf("%s ", string([]byte(enc)[:2]))
			}
			fmt.Println()
		}
	}
	enc := base64.StdEncoding.EncodeToString(h[:])
	fmt.Printf("tile at level %d index %d: %s\n", *treeLevel, *treeIndex, enc)
}
