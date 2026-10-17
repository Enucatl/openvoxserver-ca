require 'spec_helper'
require 'puppetserver/ca/host'
require 'puppetserver/ca/utils/signing_digest'

RSpec.describe Puppetserver::Ca::Utils::SigningDigest do
  it 'signs an RSA CSR with the older OpenSSL key API' do
    key = OpenSSL::PKey::RSA.new(2048)
    public_key = key.public_key
    key.singleton_class.undef_method(:public_to_der) if key.respond_to?(:public_to_der)
    host = Puppetserver::Ca::Host.new(OpenSSL::Digest::SHA256.new)

    csr = host.create_csr(name: 'legacy-agent', key: key)

    expect(csr.verify(public_key)).to be(true)
    expect(csr.signature_algorithm).to eq('sha256WithRSAEncryption')
  end
end
