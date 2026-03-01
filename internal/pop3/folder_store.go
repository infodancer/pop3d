package pop3

import (
	"bytes"
	"context"
	"io"

	"github.com/infodancer/msgstore"
)

// folderMessageStore adapts a msgstore.FolderStore to the msgstore.MessageStore
// interface for a specific folder. This allows POP3 sessions for subaddressed
// users (user+folder@domain) to present the folder as if it were their inbox,
// with no changes needed to the command layer.
type folderMessageStore struct {
	fs     msgstore.FolderStore
	folder string
}

func (a *folderMessageStore) List(ctx context.Context, mailbox string) ([]msgstore.MessageInfo, error) {
	return a.fs.ListInFolder(ctx, mailbox, a.folder)
}

func (a *folderMessageStore) Retrieve(ctx context.Context, mailbox, uid string) (io.ReadCloser, error) {
	return a.fs.RetrieveFromFolder(ctx, mailbox, a.folder, uid)
}

func (a *folderMessageStore) Delete(ctx context.Context, mailbox, uid string) error {
	return a.fs.DeleteInFolder(ctx, mailbox, a.folder, uid)
}

func (a *folderMessageStore) Expunge(ctx context.Context, mailbox string) error {
	return a.fs.ExpungeFolder(ctx, mailbox, a.folder)
}

func (a *folderMessageStore) Stat(ctx context.Context, mailbox string) (int, int64, error) {
	return a.fs.StatFolder(ctx, mailbox, a.folder)
}

func (a *folderMessageStore) RetrieveHeaders(ctx context.Context, mailbox, uid string, bodyLines int) (io.ReadCloser, error) {
	rc, err := a.fs.RetrieveFromFolder(ctx, mailbox, a.folder, uid)
	if err != nil {
		return nil, err
	}
	lines, err := extractTopLines(rc, bodyLines)
	_ = rc.Close()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, line := range lines {
		buf.WriteString(line)
		buf.WriteString("\r\n")
	}
	return io.NopCloser(&buf), nil
}
