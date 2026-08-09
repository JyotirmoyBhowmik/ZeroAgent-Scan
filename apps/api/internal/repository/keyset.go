package repository

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// KeysetCursor contains the timestamp and entity ID tuple used for keyset pagination.
type KeysetCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

// EncodeCursor encodes a timestamp and entity ID into an opaque URL-safe base64 string.
func EncodeCursor(t time.Time, id string) string {
	raw := fmt.Sprintf("%d|%s", t.UnixNano(), id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor parses an opaque base64 string back into timestamp and entity ID.
func DecodeCursor(cursorStr string) (*KeysetCursor, error) {
	if cursorStr == "" {
		return nil, nil
	}
	bytes, err := base64.RawURLEncoding.DecodeString(cursorStr)
	if err != nil {
		return nil, fmt.Errorf("keyset: invalid base64 cursor: %w", err)
	}

	parts := strings.SplitN(string(bytes), "|", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("keyset: malformed cursor payload")
	}

	var nanos int64
	_, err = fmt.Sscanf(parts[0], "%d", &nanos)
	if err != nil {
		return nil, fmt.Errorf("keyset: invalid cursor timestamp: %w", err)
	}

	return &KeysetCursor{
		CreatedAt: time.Unix(0, nanos).UTC(),
		ID:        parts[1],
	}, nil
}

// KeysetPageRequest specifies pagination parameters.
type KeysetPageRequest struct {
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit"`
}

// KeysetPageResponse represents a keyset cursor-paginated result.
type KeysetPageResponse[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
	Limit      int    `json:"limit"`
}
