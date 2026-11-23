package desktop

import (
	"errors"
	"io/fs"

	"github.com/cybericebox/icevault/pkg/vault"
)

// Every refusal that reaches the window is a stable code with parameters; the page turns it into words (srv.<code> in messages.json, for every
// language). The text of a Go error is never sent: it may name a path, come from a library or be English in a Ukrainian window.

// Codes of the errors that are not the model's: what Classify answers.
const (
	CodeNotKDBX         = "vault_not_kdbx"
	CodeKDBX3           = "vault_kdbx3"
	CodeUnsupportedKDF  = "vault_kdf"
	CodeChangedOnDisk   = "vault_changed"
	CodeVaultBusy       = "vault_busy"
	CodeVaultMissing    = "vault_missing"
	CodeVaultUnreadable = "vault_unreadable"
	CodeKeyFileMissing  = "keyfile_missing"
	CodeKeyFileUnread   = "keyfile_unreadable"
	CodeKeyFileInvalid  = "keyfile_invalid"
	CodeNoCredentials   = "type_password"
	CodeBadCredentials  = "vault_bad_credentials"
	CodeNotFound        = "not_found"
	CodeInternal        = "internal"
)

// Classify turns an error that is not a coded refusal into (status, code, parameters). Anything unknown is CodeInternal: the page shows a generic
// message with the code, and the text stays out of the window.
func Classify(err error) (status int, code string, params map[string]any) {
	params = map[string]any{}
	switch {
	case errors.Is(err, vault.ErrKDBX3):
		return 409, CodeKDBX3, params
	case errors.Is(err, vault.ErrUnsupportedKDF):
		return 409, CodeUnsupportedKDF, params
	case errors.Is(err, vault.ErrNotKDBX):
		return 409, CodeNotKDBX, params
	case errors.Is(err, vault.ErrChangedOnDisk):
		return 409, CodeChangedOnDisk, params
	case errors.Is(err, vault.ErrLocked):
		return 409, CodeVaultBusy, params
	case errors.Is(err, vault.ErrNoCredentials):
		return 400, CodeNoCredentials, params
	case errors.Is(err, vault.ErrKeyFileInvalid):
		return 409, CodeKeyFileInvalid, params
	case errors.Is(err, vault.ErrKeyFileUnreadable):
		if errors.Is(err, fs.ErrNotExist) {
			return 409, CodeKeyFileMissing, params
		}
		return 409, CodeKeyFileUnread, params
	case errors.Is(err, vault.ErrUnreadable):
		if errors.Is(err, fs.ErrNotExist) {
			return 409, CodeVaultMissing, params
		}
		return 409, CodeVaultUnreadable, params
	case errors.Is(err, vault.ErrNotFound):
		return 404, CodeNotFound, params
	case errors.Is(err, vault.ErrBadCredentials):
		return 401, CodeBadCredentials, params
	}
	return 409, CodeInternal, params
}
