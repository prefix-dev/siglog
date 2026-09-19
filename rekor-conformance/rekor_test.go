package conformance

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor-tiles/v2/pkg/client/write"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/v2/pkg/types/hashedrekord"
	"github.com/sigstore/rekor-tiles/v2/pkg/verify"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

// Uses the real upstream writer, canonical entry reconstruction, and verifier.
// Run `cargo build --bin siglog` first, then `go test -v` in this directory.
func TestRekorV2(t *testing.T) {
	binary := os.Getenv("SIGLOG_BIN")
	if binary == "" {
		binary = "../target/debug/siglog"
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	skey, vkey, err := note.GenerateKey(rand.Reader, "test.log")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	dir := t.TempDir()
	cmd := exec.Command(binary, "--mode", "rekor", "--allow-public-writes", "--origin", "test.log",
		"--private-key", skey, "--listen", addr, "--storage-backend", "fs", "--fs-root", filepath.Join(dir, "tiles"),
		"--database-url", "sqlite:"+filepath.Join(dir, "log.db")+"?mode=rwc", "--batch-max-age-ms", "5", "--checkpoint-interval", "1")
	// Do not inherit deployment secrets/configuration into a conformance run.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "RUST_LOG=error"}
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	base := "http://" + addr
	ready := false
	for i := 0; i < 100; i++ {
		resp, err := http.Get(base + "/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("server did not become ready")
	}
	writer, err := write.NewWriter(base)
	if err != nil {
		t.Fatal(err)
	}
	submit := func(key crypto.Signer, details common.PublicKeyDetails, hash crypto.Hash, certificate bool, message string) error {
		h := hash.New()
		h.Write([]byte(message))
		digest := h.Sum(nil)
		signature, err := key.Sign(rand.Reader, digest, hash)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return err
		}
		v := &pb.Verifier{KeyDetails: details, Verifier: &pb.Verifier_PublicKey{PublicKey: &pb.PublicKey{RawBytes: der}}}
		if certificate {
			template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
			if err != nil {
				return err
			}
			v.Verifier = &pb.Verifier_X509Certificate{X509Certificate: &common.X509Certificate{RawBytes: cert}}
		}
		sig := &pb.Signature{Content: signature, Verifier: v}
		request := &pb.HashedRekordRequestV002{Digest: digest, Signature: sig}
		entry, err := writer.Add(context.Background(), request)
		if err != nil {
			return err
		}
		if err := verify.VerifyLogEntry(entry, verifier); err != nil {
			return err
		}
		reconstructed, err := hashedrekord.ToEntryHash(digest, sig)
		if err != nil {
			return err
		}
		if !bytes.Equal(reconstructed, rfc6962.DefaultHasher.HashLeaf(entry.CanonicalizedBody)) {
			return fmt.Errorf("canonical entry differs from upstream reconstruction: %s", entry.CanonicalizedBody)
		}
		if err := verify.VerifyLogEntryWithHash(entry, verifier, reconstructed); err != nil {
			return err
		}
		// The complete note key hash (not the four-byte prefix) identifies the log.
		keyBytes, err := base64.StdEncoding.DecodeString(vkey[len("test.log+")+9:])
		if err != nil {
			return err
		}
		id := sha256.Sum256(append([]byte("test.log\n"), keyBytes...))
		if !bytes.Equal(id[:], entry.LogId.KeyId) {
			return fmt.Errorf("incorrect log ID")
		}
		if details == common.PublicKeyDetails_PKIX_ED25519_PH {
			// Upstream's writer must see a duplicate, not another successful append.
			if _, err := writer.Add(context.Background(), request); err == nil || !strings.Contains(err.Error(), "409") {
				return fmt.Errorf("expected upstream duplicate error, got %v", err)
			}
			payload, err := protojson.Marshal(&pb.CreateEntryRequest{Spec: &pb.CreateEntryRequest_HashedRekordRequestV002{HashedRekordRequestV002: request}})
			if err != nil {
				return err
			}
			resp, err := http.Post(base+"/api/v2/log/entries", "application/json", bytes.NewReader(payload))
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 409 || resp.Header.Get("x-log-index") != fmt.Sprint(entry.LogIndex) {
				return fmt.Errorf("incorrect duplicate status/index: %d %s", resp.StatusCode, resp.Header.Get("x-log-index"))
			}
		}
		return nil
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range []bool{false, true} {
		if err := submit(edKey, common.PublicKeyDetails_PKIX_ED25519_PH, crypto.SHA512, cert, "Ed25519 artifact"); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		curve   elliptic.Curve
		details common.PublicKeyDetails
		hash    crypto.Hash
	}{
		{elliptic.P256(), common.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, crypto.SHA256},
		{elliptic.P384(), common.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384, crypto.SHA384},
		{elliptic.P521(), common.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512, crypto.SHA512},
	} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for _, cert := range []bool{false, true} {
			if err := submit(key, tc.details, tc.hash, cert, "ECDSA artifact"); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		bits    int
		details common.PublicKeyDetails
	}{
		{2048, common.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256},
		{3072, common.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256},
		{4096, common.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256},
	} {
		key, err := rsa.GenerateKey(rand.Reader, tc.bits)
		if err != nil {
			t.Fatal(err)
		}
		for _, cert := range []bool{false, true} {
			if err := submit(key, tc.details, crypto.SHA256, cert, "RSA artifact"); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Cross a full tile boundary, including integration across multiple batches.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for batch := 0; batch < 5; batch++ {
		var wg sync.WaitGroup
		for i := 0; i < 60; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if err := submit(key, common.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, crypto.SHA256, false, fmt.Sprintf("artifact %d/%d", batch, i)); err != nil {
					t.Error(err)
				}
			}(i)
		}
		wg.Wait()
	}
}
