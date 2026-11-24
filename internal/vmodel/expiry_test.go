package vmodel

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/pkg/vault"
)

func TestExpiryStates(t *testing.T) {
	today := time.Date(2030, 1, 10, 12, 0, 0, 0, time.UTC)
	for date, want := range map[string]string{"": "", "2030-01-09": "expired", "2030-01-10": "soon", "2030-01-24": "soon", "2030-01-25": "", "nonsense": ""} {
		if got := ExpiryState(date, today, SoonDays); got != want {
			t.Errorf("%q: %q, want %q", date, got, want)
		}
	}
	if _, err := ParseDay("12.01.2030"); err == nil {
		t.Error("a date in another form")
	}
}

func TestExpiryRoundTripAndList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.kdbx")
	v, err := vault.Create(p, vault.Credentials{Password: []byte(pw)}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	m := sample()
	m.Shared[0].Expires = "2030-01-12"
	m.Other[0].Expires = "2029-12-01"
	cf := m.Connections[2]
	cf.Fields[0].Expires = "2030-01-20"
	cf.Fields = append(cf.Fields, &Field{Name: "token", Value: "t", Secret: true, Expires: "2030-01-05"})
	m.Envs[0].General[0].Expires = "2031-01-01"
	if err := Write(v, m); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	// the entries carry the native expiry: the earliest field for a connection
	if t0, ok, _ := v.Expiry("Connections/Blob store"); !ok || !t0.Equal(vault.ExpiryEnd(time.Date(2030, 1, 5, 0, 0, 0, 0, time.UTC))) {
		t.Fatalf("connection expiry: %v %v", t0, ok)
	}
	if _, ok, _ := v.Expiry("Shared/CONTACT_ADDRESS"); !ok {
		t.Fatal("shared variable has no native expiry")
	}
	got, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.Shared[0].Expires != "2030-01-12" || got.Other[0].Expires != "2029-12-01" || got.Envs[0].General[0].Expires != "2031-01-01" {
		t.Fatal("dates lost on the round trip")
	}
	f := got.Connection("Blob store").Field("token")
	if f == nil || f.Expires != "2030-01-05" || got.Connection("Blob store").Field("secret_access_key").Expires != "2030-01-20" {
		t.Fatal("field dates lost")
	}
	today := time.Date(2030, 1, 10, 12, 0, 0, 0, time.UTC)
	items := got.Expiring(today, SoonDays)
	var names []string
	for _, it := range items {
		names = append(names, it.Date+" "+it.State+" "+it.Place.String()+": "+it.Name)
	}
	want := "2029-12-01 expired other: a note|2030-01-05 expired connection Blob store: token|2030-01-12 soon shared: CONTACT_ADDRESS|2030-01-20 soon connection Blob store: secret_access_key"
	if strings.Join(names, "|") != want {
		t.Fatalf("list:\n%s\nwant\n%s", strings.Join(names, "|"), want)
	}
	// an environment run uses its imports and the connections of its products: the note (other) is not part of it
	in := got.ExpiringIn(got.Envs[0], today, 0)
	if len(in) != 1 || in[0].Name != "token" {
		t.Fatalf("used by prod: %+v", in)
	}
	// never again: the entry stops expiring
	got.Connection("Blob store").Field("token").Expires = ""
	got.Connection("Blob store").Field("secret_access_key").Expires = ""
	if err := Sync(v, got); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := v.Expiry("Connections/Blob store"); ok {
		t.Fatal("never left the native expiry on")
	}
	got.Shared[0].Expires = "soon"
	if errs := got.Check(); len(errs) == 0 {
		t.Fatal("a bad date passed Check")
	}
}

func newModelVault(t *testing.T, m *Vault) *vault.Vault {
	t.Helper()
	p := filepath.Join(t.TempDir(), "v.kdbx")
	v, err := vault.Create(p, vault.Credentials{Password: []byte(pw)}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	if err := Write(v, m); err != nil {
		t.Fatal(err)
	}
	return v
}

// A date set on a connection in a KeePass client (the native expiry, no date on any field) survives the next write of the model.
func TestNativeExpiryOfAConnectionSurvivesASync(t *testing.T) {
	v := newModelVault(t, sample())
	when := time.Date(2030, 3, 4, 12, 0, 0, 0, time.UTC)
	if err := v.SetExpiry("Connections/Blob store", when); err != nil {
		t.Fatal(err)
	}
	m, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	cf := m.Connection("Blob store")
	if cf.Field("secret_access_key").Expires != "2030-03-04" || cf.Field("bucket").Expires != "" {
		t.Fatalf("the date goes to the secret fields: %+v %+v", cf.Field("secret_access_key"), cf.Field("bucket"))
	}
	if err := Sync(v, m); err != nil {
		t.Fatal(err)
	}
	got, ok, _ := v.Expiry("Connections/Blob store")
	if !ok || vault.ExpiryDay(got).Format(DayFormat) != "2030-03-04" {
		t.Fatalf("the date was lost: %v %v", got, ok)
	}
}

// An expiry at midnight in a zone east of UTC is the same day, not the day before in UTC, and is not rewritten.
func TestLocalZoneDayIsKept(t *testing.T) {
	old := time.Local
	time.Local = time.FixedZone("east", 2*3600)
	t.Cleanup(func() { time.Local = old })
	if got := dayOf(vault.EntryInfo{Expires: time.Date(2030, 1, 11, 22, 0, 0, 0, time.UTC)}); got != "2030-01-12" {
		t.Fatalf("day %q", got)
	}
	if ExpiryState("2030-01-12", time.Date(2030, 1, 11, 23, 0, 0, 0, time.UTC), 0) != "soon" {
		t.Fatal("11 Jan 23:00 UTC is 12 Jan 01:00 there: today is the 12th")
	}
}

// A date in IceVault.Expires.<field> that is not a date does not break the vault: it is ignored with a problem, and the next write succeeds.
func TestGarbageExpiryDoesNotBreakSync(t *testing.T) {
	v := newModelVault(t, sample())
	if err := v.SetFields("Connections/Blob store", map[string]vault.Field{fExpiresPrefix + "bucket": {Value: "next week"}, fExpiresPrefix + "secret_access_key": {Value: "2030-02-01"}}); err != nil {
		t.Fatal(err)
	}
	m, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Problems) != 1 || !strings.Contains(m.Problems[0], "bucket") || m.Connection("Blob store").Field("bucket").Expires != "" {
		t.Fatalf("problems %v", m.Problems)
	}
	if err := Sync(v, m); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := connExpiry(&Connection{Fields: []*Field{{Expires: "2030-12-01"}, {Expires: "junk"}, {Expires: "2030-02-01"}}}); got != "2030-02-01" {
		t.Fatalf("connExpiry %q", got)
	}
}
