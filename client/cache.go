package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

// The height of a the full tile that Client handles. According to the
// static-ct-api spec, all logs are required to support tiles of height 8.
const fullTileHeight = 8

// FullTileWidth is the number of hashes in a full tile of height 8. Note that this only counts
// the level 0 hashes, not all the parent hashes that can be calculated from this
// number of hashes.
const FullTileWidth = 256

const tileEndpoint = "/tile"
const dataTileEndpoint = "/tile/data"
const issuerEndpoint = "/issuer"

// Client fetches and stores tiles in memory. It is not concurrent-safe.
// TODO: store tiles in Spanner.
type Client struct {
	entries    map[uint64]*DataTile // Keyed by tile index.
	tiles      map[TileKey]*Tile
	issuers    map[string][]byte // Keyed by hex-encoded fingerprint.
	httpClient *http.Client
	url        string // The URL prefix to fetch tiles from. No trailing slash.
	logName    string // For metrics.
	logSize    uint64
}

// TileKey is used to key the tiles map in the Client.
type TileKey struct {
	level uint64
	index uint64
}

// NewClient allocates a new Client.
func NewClient(client *http.Client, url string, logName string) (*Client, error) {
	if client == nil {
		return nil, fmt.Errorf("HTTP client is nil")

	}
	return &Client{
		entries:    make(map[uint64]*DataTile),
		issuers:    make(map[string][]byte),
		tiles:      make(map[TileKey]*Tile),
		httpClient: client,
		url:        url,
		logName:    logName,
	}, nil
}

// GetTile fetches a tile from the log, and stores it in the cache.
func (c *Client) GetTile(ctx context.Context, tileLevel, tileIndex, logSize uint64) (*Tile, error) {
	wantWidth := TileWidth(0, tileIndex, logSize)
	if t, ok := c.tiles[TileKey{tileLevel, tileIndex}]; ok && t.Width() >= wantWidth {
		return t, nil
	}
	url := c.url + TileAPIFragment(tileLevel, tileIndex, c.logSize)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext(%s): %w", url, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.Do: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll: %w", err)
	}
	t, err := NewTile(tileLevel, tileIndex, TileWidth(tileLevel, tileIndex, logSize), b)
	if err != nil {
		return nil, fmt.Errorf("NewTile: %w", err)
	}
	c.tiles[TileKey{tileLevel, tileIndex}] = t
	return t, nil
}

// GetHash tries to get the Hash at the coordinates from the cache, and falls
// back to fetching it from upstream if not found by calling GetTile.
func (c *Client) GetHash(ctx context.Context, treeLevel, treeIndex uint64, logSize uint64) (hash [sha256.Size]byte, err error) {
	tileLevel, tileIndex, nodeLevel, nodeIndex := TreeCoordsToTileNodeAddress(uint64(treeLevel), uint64(treeIndex))
	tile, ok := c.tiles[TileKey{tileLevel, tileIndex}]
	if !ok {
		tile, err = c.GetTile(ctx, tileLevel, tileIndex, logSize)
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("GetTile: %w", err)
		}
	}
	h, ok := tile.GetHash(nodeLevel, nodeIndex)
	if !ok {
		return [sha256.Size]byte{}, fmt.Errorf("hash not found in tile")
	}
	return h, nil
}

// GetEntries fetches entries from the log between the startEntryIndex and endEntryIndex range. This
// range is inclusive on both ends.
// TODO: fetch entries in parallel.
func (c *Client) GetEntries(ctx context.Context, startEntryIndex uint64, endEntryIndex uint64, logSize uint64) (*ct.GetEntriesResponse, error) {
	var result []ct.LeafEntry
	for currTile := startEntryIndex / FullTileWidth; currTile <= endEntryIndex/FullTileWidth; currTile++ {
		t, err := c.GetEntryTile(ctx, currTile, logSize)
		if err != nil {
			return nil, err
		}
		result = append(result, t.Entries...)
	}
	return &ct.GetEntriesResponse{Entries: result[:endEntryIndex-startEntryIndex+1]}, nil
}

// GetEntryTile fetches a tile of entries from the log or from the cache if it has already been fetched.
func (c *Client) GetEntryTile(ctx context.Context, tileIndex uint64, logSize uint64) (*DataTile, error) {
	wantWidth := TileWidth(0, tileIndex, logSize)
	if t, ok := c.entries[tileIndex]; ok && t.Width() >= wantWidth {
		return t, nil
	}
	url := c.url + DataTileAPIFragment(tileIndex, logSize)
	fmt.Println(url)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}

	// The Go client automatically decompresses the gzipped body.
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	t, err := c.NewDataTile(tileIndex, b)
	if err != nil {
		return nil, fmt.Errorf("NewEntryTile: %w", err)
	}
	c.entries[tileIndex] = t
	return t, nil
}

// GetIssuer calls the issuer endpoint.
func (c *Client) GetIssuer(fingerprint [sha256.Size]byte) ([]byte, error) {
	fingerprintHex := hex.EncodeToString(fingerprint[:])
	if issuer, ok := c.issuers[fingerprintHex]; ok {
		return issuer, nil
	}
	url := c.url + "/issuer/" + fingerprintHex
	fmt.Println(url)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	cert, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	c.issuers[fingerprintHex] = cert
	return cert, nil
}

// Tile holds a tile of merkle tree hashes. It not only contains level 0 nodes, but also the nodes
// calculated up to level 7.
type Tile struct {
	// We could do this in a 1D array, but this is easier to read.
	Nodes [][][sha256.Size]byte // Hashes are indexed by level then index.
}

// NewTile reads a tile as a byte slice and calculates the parent nodes within this tile.
func NewTile(level, index, width uint64, b []byte) (*Tile, error) {
	if int(width*sha256.Size) != len(b) {
		return nil, fmt.Errorf("width passed in is N=%d but has %d hashes", width, len(b)/sha256.Size)
	}
	nodes := [][][sha256.Size]byte{}
	rf := compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	rg := rf.NewEmptyRange(0)
	for offset := 0; offset < len(b); offset += sha256.Size {
		if err := rg.Append(b[offset:offset+sha256.Size], func(id compact.NodeID, hash []byte) {
			if len(nodes) == int(id.Level) {
				nodes = append(nodes, [][sha256.Size]byte{})
			}
			var h [sha256.Size]byte
			copy(h[:], hash)
			nodes[id.Level] = append(nodes[id.Level], h)
		}); err != nil {
			return nil, err
		}
	}
	return &Tile{nodes}, nil
}

// GetHash gets the hash at the coordinates.
func (t *Tile) GetHash(nodeLevel, nodeIndex uint64) ([sha256.Size]byte, bool) {
	if uint64(len(t.Nodes)) <= nodeLevel || uint64(len(t.Nodes[nodeLevel])) <= nodeIndex {
		return [sha256.Size]byte{}, false
	}
	return t.Nodes[nodeLevel][nodeIndex], true
}

// Width returns the number of leaves in this tile.
func (t *Tile) Width() uint64 {
	return uint64(len(t.Nodes[0]))
}

// DataTile holds a tile of entries.
type DataTile struct {
	Entries []ct.LeafEntry
}

// DataTileEntry is an entry in a static CT API data tile. See
// https://c2sp.org/static-ct-api#log-entries
// This type was copied from the Monologue client.
type DataTileEntry struct {
	// TimestampedEntry is the TimestampedEntry sub-structure of a MerkleTreeLeaf
	// according to RFC 6962, Section 3.4.
	TimestampedEntry ct.TimestampedEntry
	PreCertificate   ct.ASN1Cert
	// ExtraData        PreCertExtraData
	Fingerprint      [][sha256.Size]byte
	CertificateChain []byte
}

// NewDataTile reads a decompressed entry tile, parsing it into a DataTile.
// TODO: make this function generic we may want to support tiled logs containing other kinds of data
// in the future.
func (c *Client) NewDataTile(width uint64, contents []byte) (*DataTile, error) {
	var t DataTile
	for len(contents) > 0 {
		var entry ct.TimestampedEntry
		remaining, err := tls.Unmarshal(contents, &entry)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling timestamped entry: %w", err)
		}
		leaf := DataTileEntry{
			TimestampedEntry: entry,
		}
		switch entry.EntryType {
		case ct.X509LogEntryType:
			// No extra data for this type.
		case ct.PrecertLogEntryType:
			var preCert ct.ASN1Cert
			remaining, err = tls.Unmarshal(remaining, &preCert)
			if err != nil {
				return nil, fmt.Errorf("unmarshaling pre cert: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported entry type: %v", entry.EntryType)
		}
		remaining, err = tls.Unmarshal(remaining, &leaf.Fingerprint)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling fingerprints: %w", err)
		}
		for _, fingerprint := range leaf.Fingerprint {
			cert, err := c.GetIssuer(fingerprint)
			if err != nil {
				return nil, fmt.Errorf("get issuer: %w", err)
			}
			if len(cert) == 0 {
				return nil, fmt.Errorf("issuer is empty")
			}
			leaf.CertificateChain = append(leaf.CertificateChain, cert...)
		}
		contents = remaining

		mtl := ct.MerkleTreeLeaf{
			Version:          ct.V1,
			LeafType:         ct.TimestampedEntryLeafType,
			TimestampedEntry: &leaf.TimestampedEntry,
		}
		logEntryBytes, err := tls.Marshal(mtl)
		if err != nil {
			return nil, err
		}
		leafEntry := ct.LeafEntry{
			LeafInput: logEntryBytes,
			ExtraData: leaf.CertificateChain,
		}
		t.Entries = append(t.Entries, leafEntry)
	}
	return &t, nil
}

// The number of entries in this data tile.
func (t *DataTile) Width() uint64 {
	return uint64(len(t.Entries))
}

// TreeCoordsToTileNodeAddress returns the (TileLevel, TileIndex) in tile-space, and the
// (NodeLevel, NodeIndex) address within that tile of the specified tree node coordinates.
// Taken from
// https://github.com/transparency-dev/serverless-log/blob/68eadb49e881a8d52166ab72f4aadf7eb851b0b1/api/layout/tile.go
func TreeCoordsToTileNodeAddress(treeLevel, treeIndex uint64) (uint64, uint64, uint64, uint64) {
	tileRowWidth := uint64(1 << (fullTileHeight - treeLevel%fullTileHeight))
	tileLevel := treeLevel / fullTileHeight
	tileIndex := treeIndex / tileRowWidth
	nodeLevel := uint64(treeLevel % fullTileHeight)
	nodeIndex := uint64(treeIndex % tileRowWidth)

	return tileLevel, tileIndex, nodeLevel, nodeIndex
}

// TileWidth returns the expected number of leaves in a tile at the given location within
// a tree of the specified logSize.
// https://github.com/transparency-dev/serverless-log/blob/68eadb49e881a8d52166ab72f4aadf7eb851b0b1/api/layout/tile.go
func TileWidth(tileLevel, tileIndex, logSize uint64) uint64 {
	sizeAtLevel := logSize >> (tileLevel * fullTileHeight)
	fullTiles := sizeAtLevel / FullTileWidth
	if tileIndex < fullTiles {
		return FullTileWidth
	}
	return sizeAtLevel % FullTileWidth
}

// TileAPIFragment handles encoding the tile level, index
// and the partial tile part according to the Static CT API spec.
// https://c2sp.org/static-ct-api#merkle-tree
func TileAPIFragment(tileLevel, tileIndex, logSize uint64) string {
	fragment := fmt.Sprintf("%s/%d/%s", tileEndpoint, tileLevel, encodeN(tileIndex))
	width := TileWidth(tileLevel, tileIndex, logSize)
	if width != FullTileWidth {
		fragment += fmt.Sprintf(".p/%d", width)
	}
	return fragment
}

// DataTileAPIFragment handles encoding the tile entry index
// and the partial tile part according to the Static CT API spec.
// https://c2sp.org/static-ct-api#log-entries
func DataTileAPIFragment(tileIndex, logSize uint64) string {
	fragment := fmt.Sprintf("%s/%s", dataTileEndpoint, encodeN(tileIndex))
	if logSize%FullTileWidth != 0 && logSize/FullTileWidth == tileIndex {
		fragment += fmt.Sprintf(".p/%d", logSize%FullTileWidth)
	}
	return fragment
}

// This encodes the <N> parameter in the URL as per the Static CT API spec.
// https://c2sp.org/static-ct-api.
func encodeN(n uint64) string {
	const chunk = 1000
	enc := ""
	for n := n; n != 0; n = n / 1000 {
		part := n % 1000
		if enc == "" {
			enc = fmt.Sprintf("%03d", part)
		} else {
			enc = fmt.Sprintf("x%03d/%s", part, enc)
		}
	}
	if enc == "" {
		enc = "000"
	}
	return enc
}
