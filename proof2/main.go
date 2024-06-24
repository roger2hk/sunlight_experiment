package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"myproj/client"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

var (
	logURL  = flag.String("log_url", "https://twig.ct.letsencrypt.org/2024h1", "log operator url without trailing slash")
	oldSize = flag.Int("old_size", 586558493, "old size")
	oldHash = flag.String("old_hash", "Xi1B8o68I2jTllUVecz8Mjf7v1pObFTvrPkwR/9WZVQ=", "old hash")
)

func main() {
	ctx := context.Background()
	// httpClient := &http.Client{}
	// cpt, err := client.FetchCheckpoint(httpClient, *logURL)
	// if err != nil {
	// 	panic(err)
	// }
	cpt := client.Checkpoint{
		Size: 586558695,
		Root: "M3EDidVzoiMxPnKHeequZQAFJdJVU0ybshLgB0TxqlE=",
	}
	oldRoot, err := base64.StdEncoding.DecodeString(*oldHash)
	if err != nil {
		panic(err)
	}
	newRoot, err := base64.StdEncoding.DecodeString(cpt.Root)
	if err != nil {
		panic(err)
	}

	f, err := os.Create("testdata/data")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte(fmt.Sprintf("size: %d\nroot: %s\n", cpt.Size, cpt.Root))); err != nil {
		panic(err)
	}

	logPrefixURL, err := url.Parse(*logURL)
	if err != nil {
		panic(err)
	}
	treeProof, err := tlog.ProveTree(int64(cpt.Size), int64(*oldSize), tlog.TileHashReader(tlog.Tree{N: int64(cpt.Size), Hash: tlog.Hash(newRoot)}, &tileReader{ctx: ctx, prefix: logPrefixURL}))
	if err != nil {
		panic(err)
	}

	consistencyProof := make([][]byte, len(treeProof))
	for i, p := range treeProof {
		consistencyProof[i] = p[:]
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, uint64(*oldSize), uint64(cpt.Size), consistencyProof, oldRoot, newRoot); err != nil {
		panic(err)
	}
}

type tileReader struct {
	ctx    context.Context
	prefix *url.URL
}

func (r tileReader) Height() int {
	return 8
}

func (r tileReader) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	tileData := make([][]byte, len(tiles))
	group, ctx := errgroup.WithContext(r.ctx)
	group.SetLimit(100)
	for i := range tiles {
		group.Go(func() error {
			tileURL := r.prefix.JoinPath(tiles[i].Path())
			resp, err := download(ctx, tileURL.String())
			if err != nil {
				return err
			}
			fileName := strings.ReplaceAll(tiles[i].Path(), "/", "-")
			f, err := os.Create("testdata/" + fileName)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := f.Write(resp); err != nil {
				return err
			}
			tileData[i] = resp
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return tileData, nil
}

func (r tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {
}

func download(ctx context.Context, url string) ([]byte, error) {
	fmt.Println(url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error reading response from %s: %w", url, err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s from %s: %s", resp.Status, url, strings.TrimSpace(string(body)))
	}
	return body, nil
}
