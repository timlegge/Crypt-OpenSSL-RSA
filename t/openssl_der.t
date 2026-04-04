use strict;
use warnings;
use Test::More;
use MIME::Base64    qw/decode_base64/;
use Digest::SHA     qw/sha1_hex/;
use File::Temp      qw/ tempfile tempdir /;
use File::Slurper   qw/read_binary write_binary/;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;

BEGIN {
  unless ($ENV{AUTHOR_TESTING}) {
    print qq{1..0 # SKIP these tests are for testing by the author\n};
    exit
  }
}
my ($rsa_fh, $rsa_file) = tempfile(UNLINK => 1);

# Create a new RSA key
my $openssl = `openssl genrsa -out $rsa_file 2048 > /dev/null 2>&1`;

# Get the output as text that includes the private key PEM
my $priv_output = `openssl rsa -inform PEM -in $rsa_file -text 2>&1`;

# Get the output as text that includes the private key PEM
my $pub_output = `openssl rsa -inform PEM -in $rsa_file -pubout -text 2>&1`;


# Basic grab multi-line data between
# two tags from openssl -text output
sub get_parameter {
    my $text    = shift;
    my $start   = shift;
    my $end     = shift;

    # Fieldname may end in ':'
    $text =~ /$start:*\s*(.*?)\s*$end:*/s;
    my $parameter = $1;
    # Remove ':' and white space including newlines
    $parameter =~ s/[:\s]//g;

    # The exponent data we want is the hex data
    # with no 0x prefix
    if($parameter =~ /\((.*?)\)/ ) {
        $parameter = $1;
        $parameter =~ s/0x//g;
    }
    return $parameter;
}

# Compare a bignum to hex data
sub compare_bignum_to_hex {
    my $bn1 = shift;
    my $hex = shift;

    my $bn2 = Crypt::OpenSSL::Bignum->new_from_hex($hex);
    isa_ok($bn2, 'Crypt::OpenSSL::Bignum');
    return $bn2->cmp($bn1);
}

# Extract the values from the openssl private key output
my $priv_n = get_parameter($priv_output, 'modulus', 'publicExponent');
my $priv_e = get_parameter($priv_output, 'publicExponent', 'privateExponent');
my $priv_d = get_parameter($priv_output, 'privateExponent', 'prime1');
my $priv_p = get_parameter($priv_output, 'prime1', 'prime2');
my $priv_q = get_parameter($priv_output, 'prime2', 'exponent1');
my $priv_dmp1 = get_parameter($priv_output, 'exponent1', 'exponent2');
my $priv_dmq1 = get_parameter($priv_output, 'exponent2', 'coefficient');
my $priv_iqmp = get_parameter($priv_output, 'coefficient', '-----BEGIN PRIVATE KEY-----');
my $priv_key = get_parameter($priv_output, '-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----');

# Load the private key from the DER (base64 decoded PEM)
my $rsa = Crypt::OpenSSL::RSA->new_private_key(decode_base64($priv_key));

# Get the private key parameters
my ($n, $e, $d, $p, $q, $dmp1, $dmq1, $iqmp) = $rsa->get_key_parameters();

# Check each private key parameter to the expected values
ok(compare_bignum_to_hex($n, $priv_n) == 0, "Imported DER n parameter matches expected");
ok(compare_bignum_to_hex($e, $priv_e) == 0, "Imported DER e parameter matches expected");
ok(compare_bignum_to_hex($d, $priv_d) == 0, "Imported DER d parameter matches expected");
ok(compare_bignum_to_hex($p, $priv_p) == 0, "Imported DER p parameter matches expected");
ok(compare_bignum_to_hex($q, $priv_q) == 0, "Imported DER q parameter matches expected");
ok(compare_bignum_to_hex($dmp1, $priv_dmp1) == 0, "Imported DER dmp1 parameter matches expected");
ok(compare_bignum_to_hex($dmq1, $priv_dmq1) == 0, "Imported DER dmq1 parameter matches expected");
ok(compare_bignum_to_hex($iqmp, $priv_iqmp) == 0, "Imported DER iqmp parameter matches expected");

# Extract the public key values from the openssl public key output
my $pub_n = get_parameter($pub_output, 'modulus', 'publicExponent');
my $pub_e = get_parameter($pub_output, 'publicExponent', 'privateExponent');
my $pub_d = get_parameter($pub_output, 'privateExponent', 'prime1');
my $pub_p = get_parameter($pub_output, 'prime1', 'prime2');
my $pub_q = get_parameter($pub_output, 'prime2', 'exponent1');
my $pub_dmp1 = get_parameter($pub_output, 'exponent1', 'exponent2');
my $pub_dmq1 = get_parameter($pub_output, 'exponent2', 'coefficient');
my $pub_iqmp = get_parameter($pub_output, 'coefficient', '-----BEGIN PUBLIC KEY-----');
my $pub_key = get_parameter($pub_output, '-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----');

# Load the public key from the DER (base64 decoded PEM)
my $pub_rsa = Crypt::OpenSSL::RSA->new_public_key(decode_base64($pub_key));

# Get the private key parameters
my ($p_n, $p_e, $p_d, $p_p, $p_q, $p_dmp1, $p_dmq1, $p_iqmp) = $pub_rsa->get_key_parameters();

# Check each public key parameter to the expected values
ok(compare_bignum_to_hex($p_n, $pub_n) == 0, "Imported public DER n parameter matches expected");
ok(compare_bignum_to_hex($p_e, $pub_e) == 0, "Imported public DER e parameter matches expected");
ok(!$p_d, "Imported public DER d parameter undef as expected");
ok(!$p_p, "Imported public DER p parameter undef as expected");
ok(!$p_q, "Imported public DER q parameter undef as expected");
ok(!$p_dmp1, "Imported public DER dmp1 parameter undef as expected");
ok(!$p_dmq1, "Imported public DER dmq1 parameter undef as expected");
ok(!$p_iqmp, "Imported public DER iqmp parameter undef as expected");

done_testing();
