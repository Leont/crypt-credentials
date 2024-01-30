package Crypt::Credentials;

use strict;
use warnings;

use Carp 'croak';
use Crypt::AuthEnc::GCM qw/gcm_encrypt_authenticate gcm_decrypt_verify/;
use Crypt::URandom 0.37 'urandom_ub';
use File::Path 'make_path';
use File::Slurper qw/read_binary write_binary/;
use File::Spec::Functions qw/catdir catfile curdir rel2abs/;
use YAML::PP;

sub new {
	my ($class, %args) = @_;
	my $key_length = length $args{key};
	croak "Invalid key size($key_length)" if $key_length != 16 && $key_length != 24 && $key_length != 32;

	my $dir = rel2abs($args{dir} // catdir(curdir, 'credentials'));
	make_path($dir);

	return bless {
		key => $args{key},
		dir => $dir,
	}, $class;
}

my $ypp = YAML::PP->new;
my $format = 'a16 a16 a*';

sub _put {
	my ($self, $filename, $key, $plaintext) = @_;
	my $iv = urandom_ub(16);
	my ($ciphertext, $tag) = gcm_encrypt_authenticate('AES', $key, $iv, '', $plaintext);
	my $payload = pack $format, $iv, $tag, $ciphertext;
	write_binary($filename, $payload);
}

sub put {
	my ($self, $name, $plaintext) = @_;
	my $filename = catfile($self->{dir}, "$name.yml.enc");
	$self->_put($filename, $self->{key}, $plaintext);
	return;
}

sub put_yaml {
	my ($self, $name, @content) = @_;
	my $plaintext = $ypp->dump_string(@content);
	return $self->put($name, $plaintext);
}

sub _get {
	my ($self, $key, $filename) = @_;
	my $raw = read_binary($filename);
	my ($iv, $tag, $ciphertext) = unpack $format, $raw;
	my $plaintext = gcm_decrypt_verify('AES', $key, $iv, '', $ciphertext, $tag);
	croak 'Could not decrypt credentials file' if not defined $plaintext;
	return $plaintext;
}

sub get {
	my ($self, $name) = @_;
	my $filename = catfile($self->{dir}, "$name.yml.enc");
	croak "No such credentials '$name'" if not -e $filename;
	return $self->_get($self->{key}, $filename);
}

sub get_yaml {
	my ($self, $name) = @_;
	my $plaintext = $self->get($name);
	return $ypp->load_string($plaintext);
}

sub has {
	my ($self, $name) = @_;

	my $filename = catfile($self->{dir}, "$name.yml.enc");
	return -e $filename;
}

sub recode {
	my ($self, $new_key) = @_;

	my $key_length = length $new_key;
	croak "Invalid key size($key_length)" if $key_length != 16 && $key_length != 24 && $key_length != 32;

	opendir my $dh, $self->{dir} or croak "Could not open dir: $!";
	while (my $file = readdir $dh) {
		next unless $file =~ /\.yml\.enc$/;
		my $filename = catfile($self->{dir}, $file);

		my $plaintext = $self->_get($self->{key}, $filename);
		$self->_put($filename, $new_key, $plaintext);
	}

	$self->{key} = $new_key;

	return;
}

sub remove {
	my ($self, $name) = @_;
	my $filename = catfile($self->{dir}, "$name.yml.enc");
	return unlink($filename);
}

sub list {
	my ($self) = @_;
	opendir my $dh, $self->{dir} or croak "No such dir $self->{dir}";
	my @files = readdir $dh;
	return grep s/\.yml\.enc$//, @files;
}

1;

# ABSTRACT: Manage credential files

=head1 SYNOPSIS

 my $credentials = Crypt::Credentials->new(
   dir => $dir,
   key => $ENV{CREDENTIAL_KEY},
 );

 my $password = $credentials->get('password');

=head1 DESCRIPTION

This module implements a credentials store. Essentially it allows you to expand one secret (the key of the store) into any number of secrets.

=method new

 $self->new(key => $key, dir => $dir)

This creates a new C<Crypt::Credentials> object. It takes two named arguments: C<$key> (mandatory) is the cryptographic key used to encrypt the credentials, it must be either 16, 24, or 32 bytes long. C<$dir> is optional for the directory in which the credentials are stored, it defaults to F<./credentials>.

=method get

 $self->get($name)

This reads the credentials entry for C<$name>, or throws an exception if it can't be opened for any reason.

=method get_yaml

 $self->get_yaml($name)

Like the above, except it will decode the payload as YAML.

=method put

 $self->put($name, $value)

This will write the values to the named credentials entry.

=method put_yaml

 $self->put_yaml($name, \%values)

Like the above, but it will encode the value to YAML first.

=method has

 $self->has($name)

This checks if a credentials entry exists

=method remove

 $self->remove($name)

This removes a credentials entry. It will silently succeed if no such entry exists.

=method list

 $self->list

This will list all credential entries.

=method recode

 $self->recode($new_key)

This will recode all credential entries from the current key to the new one.
