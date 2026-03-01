package pop3

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/infodancer/msgstore"
)

// sessionPipeStore implements msgstore.MessageStore by routing all operations
// through the session pipe protocol (fds 5 and 6 in the protocol-handler).
//
// On the first List call it writes the auth signal to the auth pipe (fd 4),
// closes that pipe so the dispatcher can unblock, then performs the MAILBOX
// handshake with mail-session before executing the LIST.
type sessionPipeStore struct {
	authPipeW io.WriteCloser // fd 4: written once, then closed
	sessR     *bufio.Reader  // fd 5: responses from mail-session
	sessW     io.Writer      // fd 6: commands to mail-session
	ready     bool
}

// NewSessionPipeStore creates a sessionPipeStore from the three pipe ends used
// in the subprocess protocol-handler.
func NewSessionPipeStore(authPipeW io.WriteCloser, sessR io.Reader, sessW io.Writer) msgstore.MessageStore {
	return &sessionPipeStore{
		authPipeW: authPipeW,
		sessR:     bufio.NewReader(sessR),
		sessW:     sessW,
	}
}

// handshake sends the auth signal and MAILBOX command on the first List call.
func (p *sessionPipeStore) handshake(mailbox string) error {
	// The mailbox is also the fully-qualified username (localpart@domain) per the
	// address contract: AuthRouter guarantees User.Mailbox == base@domain.
	sig := &authSignal{Version: 1, Username: mailbox}
	if err := writeAuthSignal(p.authPipeW, sig); err != nil {
		return fmt.Errorf("write auth signal: %w", err)
	}
	if err := p.authPipeW.Close(); err != nil {
		return fmt.Errorf("close auth pipe: %w", err)
	}

	if _, err := fmt.Fprintf(p.sessW, "MAILBOX %s\r\n", mailbox); err != nil {
		return fmt.Errorf("send MAILBOX: %w", err)
	}
	line, err := p.sessR.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read MAILBOX response: %w", err)
	}
	if !strings.HasPrefix(strings.TrimRight(line, "\r\n"), "+OK") {
		return fmt.Errorf("MAILBOX rejected: %s", strings.TrimRight(line, "\r\n"))
	}

	p.ready = true
	return nil
}

// readOK reads one response line and returns an error if it is not "+OK …".
func (p *sessionPipeStore) readOK(op string) error {
	line, err := p.sessR.ReadString('\n')
	if err != nil {
		return fmt.Errorf("%s: read response: %w", op, err)
	}
	if !strings.HasPrefix(strings.TrimRight(line, "\r\n"), "+OK") {
		return fmt.Errorf("%s error: %s", op, strings.TrimRight(line, "\r\n"))
	}
	return nil
}

// List implements msgstore.MessageStore.
// On the first call it performs the auth/MAILBOX handshake.
// Wire: send "LIST\r\n"; receive "+OK <count> <octets>\r\n" then <count> lines
// of "<uid> <size>\r\n".
func (p *sessionPipeStore) List(ctx context.Context, mailbox string) ([]msgstore.MessageInfo, error) {
	if !p.ready {
		if err := p.handshake(mailbox); err != nil {
			return nil, err
		}
	}

	if _, err := fmt.Fprintf(p.sessW, "LIST\r\n"); err != nil {
		return nil, fmt.Errorf("send LIST: %w", err)
	}

	// "+OK <count> <octets>"
	header, err := p.sessR.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read LIST header: %w", err)
	}
	header = strings.TrimRight(header, "\r\n")
	if !strings.HasPrefix(header, "+OK") {
		return nil, fmt.Errorf("LIST error: %s", header)
	}

	// Parse message count from "+OK <count> …"
	fields := strings.Fields(strings.TrimPrefix(header, "+OK"))
	if len(fields) == 0 {
		return nil, fmt.Errorf("LIST: missing count in %q", header)
	}
	count, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, fmt.Errorf("LIST: invalid count %q", fields[0])
	}

	msgs := make([]msgstore.MessageInfo, 0, count)
	for i := 0; i < count; i++ {
		entry, err := p.sessR.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("LIST entry %d: %w", i+1, err)
		}
		entry = strings.TrimRight(entry, "\r\n")
		// "<uid> <size>"
		f := strings.Fields(entry)
		if len(f) != 2 {
			return nil, fmt.Errorf("LIST entry %d: malformed %q", i+1, entry)
		}
		size, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("LIST entry %d: invalid size %q", i+1, f[1])
		}
		msgs = append(msgs, msgstore.MessageInfo{UID: f[0], Size: size})
	}
	return msgs, nil
}

// Retrieve implements msgstore.MessageStore.
// Wire: send "GET <uid>\r\n"; receive "+DATA <size>\r\n" then exactly <size> bytes.
func (p *sessionPipeStore) Retrieve(ctx context.Context, mailbox, uid string) (io.ReadCloser, error) {
	if _, err := fmt.Fprintf(p.sessW, "GET %s\r\n", uid); err != nil {
		return nil, fmt.Errorf("send GET: %w", err)
	}
	line, err := p.sessR.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read GET response: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "+DATA") {
		return nil, fmt.Errorf("GET error: %s", line)
	}
	sizeStr := strings.TrimSpace(strings.TrimPrefix(line, "+DATA"))
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GET: invalid data size %q", sizeStr)
	}
	// Return a reader over exactly <size> bytes; sessR retains ownership.
	return io.NopCloser(io.LimitReader(p.sessR, size)), nil
}

// Delete implements msgstore.MessageStore.
// Wire: send "DELETE <uid>\r\n"; receive "+OK\r\n".
func (p *sessionPipeStore) Delete(ctx context.Context, mailbox, uid string) error {
	if _, err := fmt.Fprintf(p.sessW, "DELETE %s\r\n", uid); err != nil {
		return fmt.Errorf("send DELETE: %w", err)
	}
	return p.readOK("DELETE")
}

// Expunge implements msgstore.MessageStore.
// Sends COMMIT which causes mail-session to apply all pending deletions.
// Wire: send "COMMIT\r\n"; receive "+OK\r\n".
func (p *sessionPipeStore) Expunge(ctx context.Context, mailbox string) error {
	if _, err := fmt.Fprintf(p.sessW, "COMMIT\r\n"); err != nil {
		return fmt.Errorf("send COMMIT: %w", err)
	}
	return p.readOK("COMMIT")
}

// Stat implements msgstore.MessageStore.
// Wire: send "STAT\r\n"; receive "+OK <count> <octets>\r\n".
func (p *sessionPipeStore) Stat(ctx context.Context, mailbox string) (int, int64, error) {
	if _, err := fmt.Fprintf(p.sessW, "STAT\r\n"); err != nil {
		return 0, 0, fmt.Errorf("send STAT: %w", err)
	}
	line, err := p.sessR.ReadString('\n')
	if err != nil {
		return 0, 0, fmt.Errorf("read STAT response: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "+OK") {
		return 0, 0, fmt.Errorf("STAT error: %s", line)
	}
	// "+OK <count> <octets>"
	fields := strings.Fields(strings.TrimPrefix(line, "+OK"))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("STAT: malformed response %q", line)
	}
	count, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, fmt.Errorf("STAT: invalid count %q", fields[0])
	}
	total, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("STAT: invalid total %q", fields[1])
	}
	return count, total, nil
}
