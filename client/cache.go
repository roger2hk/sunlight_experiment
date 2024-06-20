package client

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/transparency-dev/merkle/rfc6962"
)

// TODO: have some kind of blob storage for tiles.
type Cache struct {
	tiles   map[string]*Tile
	client  *http.Client
	url     string
	logSize int
}

const fullTileWidth = 256

func NewCache(client *http.Client, url string, logSize int) *Cache {
	return &Cache{
		tiles:   make(map[string]*Tile),
		client:  client,
		url:     url,
		logSize: logSize,
	}
}

func (c *Cache) GetTile(ctx context.Context, tileLevel, tileIndex int) (*Tile, error) {
	if t, ok := c.tiles[TileKey(tileLevel, tileIndex)]; ok {
		return t, nil
	}
	width := TileSize(uint64(tileLevel), uint64(tileIndex), uint64(c.logSize))
	url := fmt.Sprintf("%s/tile/8/%d/%s", c.url, tileLevel, EncodeTileIndex(uint64(tileIndex)))
	if width != fullTileWidth {
		url += fmt.Sprintf(".p/%d", width)
	}
	fmt.Println(url)
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	t, err := NewTile(tileLevel, tileIndex, width, b)
	if err != nil {
		return nil, fmt.Errorf("NewTile: %w", err)
	}
	// TODO: store these tiles in blob store?
	c.tiles[TileKey(tileLevel, tileIndex)] = t
	return t, nil
}

func (c *Cache) GetHash(ctx context.Context, treeLevel, treeIndex int) (hash [sha256.Size]byte, err error) {
	tileLevel, tileIndex, nodeLevel, nodeIndex := TreeCoordsToTileNodeAddress(uint64(treeLevel), uint64(treeIndex))
	tile, ok := c.tiles[TileKey(int(tileLevel), int(tileIndex))]
	if !ok {
		tile, err = c.GetTile(ctx, int(tileLevel), int(tileIndex))
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("getTile: %w", err)
		}
	}
	h, ok := tile.GetHash(int(nodeLevel), int(nodeIndex))
	if !ok {
		return [sha256.Size]byte{}, fmt.Errorf("hash not found in tile")
	}
	return h, nil
}

type Tile struct {
	level int
	index int
	width int // >= 1, <= 256.
	// We could do this in one array, but this is easier to read.
	Nodes [][][sha256.Size]byte // Level, index.
}

func NewTile(level int, index int, width uint64, b []byte) (*Tile, error) {
	if len(b)%sha256.Size != 0 {
		return nil, fmt.Errorf("malformed tile")
	}
	if int(width*sha256.Size) != len(b) {
		return nil, fmt.Errorf("tile's passed in width is N=%d but has %d hashes", width, len(b)/sha256.Size)
	}
	nodes := [][][sha256.Size]byte{
		make([][sha256.Size]byte, width),
	}
	// Fill in the first row.
	for i := 0; i < int(width); i += 1 {
		h := b[(i * sha256.Size):((i + 1) * sha256.Size)]
		copy(nodes[0][i][:], h)
	}
	// Compute parent rows based on previous rows.
	h := rfc6962.DefaultHasher
	layer := 1
	for {
		if len(nodes[layer-1]) == 1 {
			break
		}
		nodes = append(nodes, make([][sha256.Size]byte, len(nodes[layer-1])/2))
		for i := 0; i < len(nodes[layer]); i += 1 {
			l, r := nodes[layer-1][i*2], nodes[layer-1][(i*2)+1]
			p := h.HashChildren(l[:], r[:])
			copy(nodes[layer][i][:], p)
		}
		layer += 1
	}
	return &Tile{
		level: level,
		index: index,
		width: int(width),
		Nodes: nodes,
	}, nil
}

func (t *Tile) GetHash(nodeLevel, nodeIndex int) ([sha256.Size]byte, bool) {
	if len(t.Nodes) <= nodeLevel || len(t.Nodes[nodeLevel]) <= nodeIndex {
		return [sha256.Size]byte{}, false
	}
	return t.Nodes[nodeLevel][nodeIndex], true
}

// TreeCoordsToTileNodeAddress returns the (TileLevel, TileIndex) in tile-space, and the
// (NodeLevel, NodeIndex) address within that tile of the specified tree node co-ordinates.
func TreeCoordsToTileNodeAddress(treeLevel, treeIndex uint64) (uint64, uint64, uint, uint64) {
	tileRowWidth := uint64(1 << (8 - treeLevel%8))
	tileLevel := treeLevel / 8
	tileIndex := treeIndex / tileRowWidth
	nodeLevel := uint(treeLevel % 8)
	nodeIndex := uint64(treeIndex % tileRowWidth)

	return tileLevel, tileIndex, nodeLevel, nodeIndex
}

// TileSize returns the expected number of leaves in a tile at the given location within
// a tree of the specified logSize, or 0 if the tile is expected to be fully populated.
func TileSize(tileLevel, tileIndex, logSize uint64) uint64 {
	sizeAtLevel := logSize >> (tileLevel * 8)
	fullTiles := sizeAtLevel / 256
	if tileIndex < fullTiles {
		return 256
	}
	return sizeAtLevel % 256
}

func TileKey(level, index int) string {
	return fmt.Sprintf("%d|%d", level, index)
}

// In accordance to the sunlight spec. The encoding of <N>.
// https://github.com/C2SP/C2SP/blob/main/sunlight.md
func EncodeTileIndex(index uint64) string {
	const chunk = 1000
	enc := ""
	for {
		part := index % chunk
		if enc == "" {
			enc = fmt.Sprintf("%03d", part)
		} else {
			enc = fmt.Sprintf("x%03d/%s", part, enc)
		}
		index = index / 1000
		if index == 0 {
			break
		}
	}
	return enc
}

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
