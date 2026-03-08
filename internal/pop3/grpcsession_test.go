package pop3

import (
	"io"
	"testing"
)

func TestGrpcSessionStore_HandshakeFailsOnEmptyMailbox(t *testing.T) {
	// Create a pipe pair for the auth pipe and session response pipe.
	authR, authW := io.Pipe()
	defer authR.Close()

	sessR, sessW := io.Pipe()
	defer sessR.Close()
	defer sessW.Close()

	store := NewGrpcSessionStore(authW, sessR)

	// List with empty mailbox should fail validation.
	_, err := store.List(t.Context(), "")
	if err == nil {
		t.Fatal("expected error for empty mailbox")
	}
}

func TestGrpcSessionStore_HandshakeFailsOnWhitespaceMailbox(t *testing.T) {
	authR, authW := io.Pipe()
	defer authR.Close()

	sessR, sessW := io.Pipe()
	defer sessR.Close()
	defer sessW.Close()

	store := NewGrpcSessionStore(authW, sessR)

	_, err := store.List(t.Context(), "user name@example.com")
	if err == nil {
		t.Fatal("expected error for mailbox with whitespace")
	}
}

func TestGrpcSessionStore_DoubleHandshakeReturnsError(t *testing.T) {
	authR, authW := io.Pipe()
	defer authR.Close()

	sessR, sessW := io.Pipe()
	defer sessR.Close()
	defer sessW.Close()

	store := NewGrpcSessionStore(authW, sessR)

	// First call fails (empty mailbox → validation error).
	_, _ = store.List(t.Context(), "")

	// Second call should return "already failed" error.
	_, err := store.List(t.Context(), "user@example.com")
	if err == nil {
		t.Fatal("expected error on second call after failed handshake")
	}
	if err.Error() != "gRPC session handshake already failed; store is not usable" {
		t.Errorf("unexpected error: %v", err)
	}
}
