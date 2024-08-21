package client

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type Checkpoint struct {
	Size int
	Root string
}

func FetchCheckpoint(client *http.Client, url string) (*Checkpoint, error) {
	fullURL := url + "/checkpoint"
	r, err := client.Get(fullURL)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("%s returned %d", fullURL, r.StatusCode)
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	size, err := strconv.Atoi(lines[1])
	if err != nil {
		return nil, err
	}
	return &Checkpoint{
		Size: size,
		Root: lines[2],
	}, nil
}
