# Extract the exact flat regular members of a bounded USTAR CLI bundle.

use strict;
use warnings;
use Fcntl qw(O_CREAT O_EXCL O_WRONLY);
use IO::Uncompress::Gunzip;

my ($archive, $destination) = @ARGV;
my %limits = ('exacopy' => 268435456, 'release.manifest' => 4096, 'release.sig' => 1024);
my %seen;
my $block = 512;
my $zero_block = "\0" x $block;

sub refuse {
	die "invalid ExaCopy release archive: $_[0]\n";
}

open my $input, '<:raw', $archive or refuse('cannot open gzip file');
# A fixed-size gzip header rules out unbounded optional header strings.
my $gzip_header;
my $header_bytes = read($input, $gzip_header, 10);
defined($header_bytes) && $header_bytes == 10 && substr($gzip_header, 0, 4) eq "\x1f\x8b\x08\x00"
	or refuse('unsupported gzip header');
seek($input, 0, 0) or refuse('cannot rewind gzip file');
my $gzip = IO::Uncompress::Gunzip->new(
	$input, Strict => 1, Transparent => 0, MultiStream => 0, BlockSize => 8192,
) or refuse('cannot open gzip stream');

sub exact_read {
	my ($length) = @_;
	my $output = '';
	while (length($output) < $length) {
		my $count = $gzip->read(my $chunk, $length - length($output));
		defined($count) && $count > 0 or refuse('truncated or corrupt gzip stream');
		$output .= $chunk;
	}
	return $output;
}

for (1 .. keys %limits) {
	my $header = exact_read($block);
	substr($header, 257, 8) eq "ustar\x0000" or refuse('expected a USTAR member');
	substr($header, 156, 1) eq '0' && substr($header, 157, 100) eq "\0" x 100
		&& substr($header, 345, 155) eq "\0" x 155
		or refuse('only flat regular members are supported');

	my ($name) = substr($header, 0, 100) =~ /\A([^\x00]+)\x00+\z/;
	defined($name) && exists($limits{$name}) && !$seen{$name}++
		or refuse('unexpected or duplicate member name');
	my ($size) = substr($header, 124, 12) =~ /\A([0-7]{11})\x00\z/;
	defined($size) or refuse('invalid tar size field');
	$size = oct($size);
	$size > 0 && $size <= $limits{$name} or refuse('member size outside the release profile');

	my ($checksum) = substr($header, 148, 8) =~ /\A([0-7]{6})\x00 \z/;
	substr($header, 148, 8, ' ' x 8);
	defined($checksum) && oct($checksum) == unpack('%32C*', $header)
		or refuse('USTAR header checksum mismatch');

	# The accepted name is an exact known basename. Ignore archive metadata,
	# and open a new owner-private file in the caller's private directory.
	sysopen my $output, "$destination/$name", O_WRONLY | O_CREAT | O_EXCL, 0600
		or refuse('cannot create bundle file');
	binmode($output, ':raw') or refuse('cannot set binary file mode');
	my $remaining = $size;
	while ($remaining > 0) {
		my $length = $remaining < 65536 ? $remaining : 65536;
		print {$output} exact_read($length) or refuse('cannot write bundle file');
		$remaining -= $length;
	}
	close($output) or refuse('cannot close bundle file');
	my $padding = ($block - $size % $block) % $block;
	exact_read($padding) eq "\0" x $padding or refuse('nonzero tar member padding');
}

exact_read($block * 2) eq $zero_block x 2 or refuse('unexpected member or missing tar terminator');
# USTAR writers can pad the terminator to a standard 20-block tar record.
for my $trailing_block (1 .. 19) {
	my $count = $gzip->read(my $data, $block);
	defined($count) && $count >= 0 or refuse('corrupt gzip trailer');
	if ($count == 0) {
		my $tail_bytes = read($input, my $trailing, 1);
		length($gzip->trailingData()) == 0 && defined($tail_bytes) && $tail_bytes == 0
			or refuse('trailing data after gzip stream');
		exit 0;
	}
	$count == $block && $data eq $zero_block && $trailing_block <= 18
		or refuse('unexpected data after tar terminator');
}
