use strict;
use warnings;
use Test::More;
use MIME::Base64;
use Crypt::OpenSSL::RSA;

BEGIN { plan tests => 14 }

# --- Generate a key pair for testing ---

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);

# --- Extract PEM public keys ---

my $pkcs1_pem = $rsa->get_public_key_string();        # PKCS#1 (BEGIN RSA PUBLIC KEY)
my $x509_pem  = $rsa->get_public_key_x509_string();   # X.509 (BEGIN PUBLIC KEY)

# --- Convert PEM to DER by stripping headers and base64-decoding ---

sub pem_to_der {
    my ($pem) = @_;
    $pem =~ s/-----BEGIN [^-]+-----//;
    $pem =~ s/-----END [^-]+-----//;
    $pem =~ s/\s+//g;
    return decode_base64($pem);
}

my $pkcs1_der = pem_to_der($pkcs1_pem);
my $x509_der  = pem_to_der($x509_pem);

# Sanity check: DER data starts with ASN.1 SEQUENCE tag
is( ord(substr($pkcs1_der, 0, 1)), 0x30, "PKCS#1 DER starts with SEQUENCE tag" );
is( ord(substr($x509_der, 0, 1)),  0x30, "X.509 DER starts with SEQUENCE tag" );

# --- Load DER keys via new_public_key ---

my ($pub_from_x509_der, $pub_from_pkcs1_der);

ok( $pub_from_x509_der = Crypt::OpenSSL::RSA->new_public_key($x509_der),
    "new_public_key loads X.509 DER key" );

ok( $pub_from_pkcs1_der = Crypt::OpenSSL::RSA->new_public_key($pkcs1_der),
    "new_public_key loads PKCS#1 DER key" );

# --- Verify round-trip: DER-loaded keys produce the same PEM output ---

is( $pub_from_x509_der->get_public_key_x509_string(), $x509_pem,
    "X.509 DER key exports to same X.509 PEM" );

is( $pub_from_x509_der->get_public_key_string(), $pkcs1_pem,
    "X.509 DER key exports to same PKCS#1 PEM" );

is( $pub_from_pkcs1_der->get_public_key_x509_string(), $x509_pem,
    "PKCS#1 DER key exports to same X.509 PEM" );

is( $pub_from_pkcs1_der->get_public_key_string(), $pkcs1_pem,
    "PKCS#1 DER key exports to same PKCS#1 PEM" );

# --- Verify DER-loaded keys can actually verify signatures ---

$rsa->use_sha256_hash();
my $plaintext = "Hello, DER world!";
my $sig = $rsa->sign($plaintext);

$pub_from_x509_der->use_sha256_hash();
ok( $pub_from_x509_der->verify($plaintext, $sig),
    "X.509 DER-loaded key verifies signature" );

$pub_from_pkcs1_der->use_sha256_hash();
ok( $pub_from_pkcs1_der->verify($plaintext, $sig),
    "PKCS#1 DER-loaded key verifies signature" );

# --- Error cases ---

# DER-like data that isn't a valid key
eval { Crypt::OpenSSL::RSA->new_public_key("\x30\x00") };
ok( $@, "new_public_key croaks on truncated DER data" );

# Completely bogus binary data (not starting with 0x30)
eval { Crypt::OpenSSL::RSA->new_public_key("\x01\x02\x03\x04") };
like( $@, qr/unrecognized key format/,
    "new_public_key gives helpful error on random binary data" );

# Empty string
eval { Crypt::OpenSSL::RSA->new_public_key("") };
like( $@, qr/unrecognized key format/,
    "new_public_key gives helpful error on empty string" );

# PEM header for wrong type
eval { Crypt::OpenSSL::RSA->new_public_key("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----\n") };
like( $@, qr/unrecognized key format/,
    "new_public_key gives helpful error on certificate PEM" );
