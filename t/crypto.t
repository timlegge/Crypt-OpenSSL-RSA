use strict;
use Test::More;

use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;

# Tests for encrypt/decrypt error paths, boundary conditions, and edge cases.
# These cover gaps not addressed by rsa.t or padding.t.

plan tests => 13;

Crypt::OpenSSL::Random::random_seed("OpenSSL needs at least 32 bytes.");
Crypt::OpenSSL::RSA->import_random_seed();

my $rsa  = Crypt::OpenSSL::RSA->generate_key(2048);
my $rsa2 = Crypt::OpenSSL::RSA->generate_key(2048);
my $key_size = $rsa->size();  # 256 bytes for 2048-bit key

# --- OAEP boundary tests ---

$rsa->use_pkcs1_oaep_padding();
my $oaep_max = $key_size - 42;  # SHA-1 OAEP overhead

# Max-length plaintext that fits OAEP
{
    my $max_data = "x" x $oaep_max;
    my $ct = eval { $rsa->encrypt($max_data) };
    ok(!$@, "OAEP encrypt at max plaintext length ($oaep_max bytes) succeeds")
        or diag $@;
    SKIP: {
        skip "encryption failed", 1 if $@;
        is($rsa->decrypt($ct), $max_data,
            "OAEP max-length plaintext round-trips correctly");
    }
}

# One byte over max should fail
{
    my $too_long = "x" x ($oaep_max + 1);
    eval { $rsa->encrypt($too_long) };
    ok($@, "OAEP encrypt with plaintext one byte over max croaks");
}

# --- No-padding boundary tests ---

$rsa->use_no_padding();

# Too-short data for no-padding (requires exactly key_size bytes)
{
    eval { $rsa->encrypt("x" x ($key_size - 1)) };
    ok($@, "no-padding encrypt with data shorter than key size croaks");
}

# Too-long data for no-padding
{
    eval { $rsa->encrypt("x" x ($key_size + 1)) };
    ok($@, "no-padding encrypt with data longer than key size croaks");
}

# --- Decrypt error cases ---

$rsa->use_pkcs1_oaep_padding();

# Decrypt garbage data
{
    my $garbage = "G" x $key_size;
    eval { $rsa->decrypt($garbage) };
    ok($@, "decrypt of garbage data croaks");
}

# Decrypt truncated ciphertext
{
    my $ct = $rsa->encrypt("test data");
    my $truncated = substr($ct, 0, length($ct) - 10);
    eval { $rsa->decrypt($truncated) };
    ok($@, "decrypt of truncated ciphertext croaks");
}

# Decrypt with wrong private key
{
    $rsa2->use_pkcs1_oaep_padding();
    my $ct = $rsa->encrypt("wrong key test");
    eval { $rsa2->decrypt($ct) };
    ok($@, "decrypt with wrong private key croaks");
}

# Decrypt bit-flipped ciphertext
{
    my $ct = $rsa->encrypt("bit flip test");
    my $flipped = $ct;
    substr($flipped, length($flipped) / 2, 1) ^= "\x01";
    eval { $rsa->decrypt($flipped) };
    ok($@, "decrypt of bit-flipped ciphertext croaks");
}

# --- Empty string ---

{
    my $ct = eval { $rsa->encrypt("") };
    ok(!$@, "OAEP encrypt of empty string succeeds") or diag $@;
    SKIP: {
        skip "encryption failed", 1 if $@;
        is($rsa->decrypt($ct), "",
            "OAEP empty string round-trips correctly");
    }
}

# --- Binary data with embedded NULs ---

{
    my $binary = "\x00\x01\x00\xFF\x00" . ("\x00" x 50) . "\xFE";
    my $ct = $rsa->encrypt($binary);
    is($rsa->decrypt($ct), $binary,
        "binary data with embedded NUL bytes round-trips correctly");
}

# --- PSS padding cannot be used for encryption ---

{
    $rsa->use_pkcs1_pss_padding();
    eval { $rsa->encrypt("test") };
    ok($@, "PSS padding cannot be used for encryption");
}
