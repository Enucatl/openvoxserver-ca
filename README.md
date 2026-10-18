# OpenVox Server's CA CLI Library

This gem provides the functionality behind the OpenVox Server CA interactions.
The actual CLI executable lives within the OpenVox Server project.
This is a community implementation of the `puppetserver-ca` gem. 


## Installation

You may install it yourself with:

    $ gem install openvoxserver-ca


## Usage

For initial CA setup, we provide two options. These need to be run before starting
Puppet Server for the first time.

To set up a default CA, with a self-signed root cert and an intermediate signing cert:
```
puppetserver ca setup
```

To create an ML-DSA-44 root, intermediate signing CA, and server identity:
```sh
puppetserver ca setup --key-type mldsa44
```

The flag only affects this setup command; omitting it (or using `--key-type rsa`)
retains RSA generation, regardless of an agent's `key_type` configuration.
ML-DSA-44 requires native Ruby OpenSSL with OpenSSL 3.5 or later. Configure a
compatible TLS provider separately before starting the server, and use capable
agents with the new CA trust. Set agent `key_type = mldsa44` for new ML-DSA agent
keys; existing identities are not migrated. Setup refuses to overwrite existing
CA output files. Explicit ML-DSA setup also refuses an existing server key of a
different type; it preserves an existing ML-DSA-44 pair.

To import a custom CA:
```
puppetserver ca import --cert-bundle certs.pem --crl-chain crls.pem --private-key ca_key.pem
```

For an ML-DSA-44 import, first place an ML-DSA-44 private key and its public PEM
at the configured `hostprivkey` and `hostpubkey` paths. Both files must exist;
without them, server key generation retains its RSA default. For example, after
creating the configured key directories:

```sh
/opt/puppetlabs/puppet/bin/ruby -ropenssl -e '
  key = OpenSSL::PKey.generate_key("ML-DSA-44")
  File.open(ARGV[0], "wx", 0640) { |file| file.write(key.private_to_pem) }
  File.open(ARGV[1], "wx", 0644) { |file| file.write(key.public_to_pem) }
' HOSTPRIVKEY HOSTPUBKEY
```

Then run `ca import` with `--config puppet.conf`, the ML-DSA-44 subordinate private
key, its certificate chain, and the issuer CRL chain. Set `ca_ttl` within the
issuer's remaining lifetime. Existing CA output files and `hostcert` cause import
to refuse replacement; existing server key pairs are preserved. Import writes a
leaf-only `hostcert`, so configure the TLS server to send its issuer chain too.
This path was tested with bundled Ruby 4.0.7, Ruby OpenSSL 4.0.2 and OpenSSL 3.5.9;
the running server also needs a compatible ML-DSA TLS provider.

The remaining actions provided by this gem require a running OpenVox Server (Puppet Server), since
it primarily uses the CA's API endpoints to do its work. The following examples
assume that you are using the gem packaged within OpenVox Server.

To sign a pending certificate request:
```
puppetserver ca sign --certname foo.example.com
```

To list certificates and CSRs:
```
puppetserver ca list --all
```

To revoke a signed certificate:
```
puppetserver ca revoke --certname foo.example.com
```

To revoke the cert and clean up all SSL files for a given certname:
```
puppetserver ca clean --certname foo.example.com
```

To create a new keypair and certificate for a certname:
```
puppetserver ca generate --certname foo.example.com
```

To remove duplicated entries from Puppet's CRL:
```
puppetserver ca prune
```

To enable verbose mode:
```
puppetserver ca --verbose <action>
```

For more details, see the help output:
```
puppetserver ca --help
```

This code in this project is licensed under the Apache Software License v2,
please see the included [License](https://github.com/OpenVoxProject/openvoxserver-ca-cli/blob/main/LICENSE.md)
for more details.


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then,
run `bundle exec rake spec` to run the tests. You can also run `bin/console` for an
interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.

### Testing
To test your changes on a VM:
1. Build the gem with your changes: `gem build openvoxserver-ca.gemspec`
1. Copy the gem to your VM: `scp openvoxserver-ca-<version>.gem <your-vm>:.`
1. Install openvox-server by installing the relevant release package and then installing the openvox-server package. For example:
    ```
    $ wget https://yum.voxpupuli.org/openvox8-release-el-9.noarch.rpm
    $ rpm -i openvox8-release-el-9.noarch.rpm
    $ yum update
    $ yum install -y openvox-server
    ```
1. Restart your shell so that puppet's bin dir is on your $PATH: `exec bash`
1. Install the gem into puppet's gem directory using puppet's gem command:
    ```
    $ /opt/puppetlabs/puppet/bin/gem install --install-dir "/opt/puppetlabs/puppet/lib/ruby/vendor_gems" openvoxserver-ca-<version>.gem
    ```
1. To confirm that installation was successful, run `puppetserver ca --help`

## Contributing & Support

Bug reports and feature requests are welcome via GitHub issues.

For interactive questions feel free to post to #puppet or #puppet-dev on the Puppet Community Slack channel.

Contributions are welcome at https://github.com/OpenVoxProject/openvoxserver-ca-cli/pulls.
Contributors should both be sure to read the
[contributing document](https://github.com/OpenVoxProject/openvoxserver-ca-cli/blob/main/CONTRIBUTING.md)
and sign the [contributor license agreement](https://cla.puppet.com/).

Everyone interacting with the project’s codebase, issue tracker, etc is expected
to follow the
[code of conduct](https://github.com/OpenVoxProject/openvoxserver-ca-cli/blob/main/CODE_OF_CONDUCT.md).
