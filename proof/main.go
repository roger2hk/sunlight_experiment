package main

import (
	"context"
	"encoding/base64"
	"flag"
	"myproj/client"
	"net/http"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

var (
	logURL  = flag.String("log_url", "https://twig.ct.letsencrypt.org/2024h1", "log operator url without trailing slash")
	oldSize = flag.Int("old_size", 586558493, "old size")
	oldHash = flag.String("old_hash", "Xi1B8o68I2jTllUVecz8Mjf7v1pObFTvrPkwR/9WZVQ=", "old size")
)

func main() {
	ctx := context.Background()
	httpClient := &http.Client{}
	cpt, err := client.FetchCheckpoint(httpClient, *logURL)
	if err != nil {
		panic(err)
	}
	oldRoot, err := base64.StdEncoding.DecodeString(*oldHash)
	if err != nil {
		panic(err)
	}
	newRoot, err := base64.StdEncoding.DecodeString(cpt.Root)
	if err != nil {
		panic(err)
	}
	nodes, err := proof.Consistency(uint64(*oldSize), uint64(cpt.Size))
	if err != nil {
		panic(err)
	}
	cache := client.NewCache(httpClient, *logURL, cpt.Size)
	consistencyProof := make([][]byte, len(nodes.IDs))
	for i, id := range nodes.IDs {
		h, err := cache.GetHash(ctx, int(id.Level), int(id.Index))
		if err != nil {
			panic(err)
		}
		consistencyProof[i] = h[:]
	}
	rehashedProof, err := nodes.Rehash(consistencyProof, rfc6962.DefaultHasher.HashChildren)
	if err != nil {
		panic(err)
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, uint64(*oldSize), uint64(cpt.Size), rehashedProof, oldRoot, newRoot); err != nil {
		panic(err)
	}
}
