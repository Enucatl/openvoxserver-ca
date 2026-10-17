require 'spec_helper'
require 'utils/ssl'
require 'puppetserver/ca/action/import'
require 'puppetserver/ca/action/prune'
require 'puppetserver/ca/logger'

RSpec.describe 'ML-DSA-44 CA import' do
  include Utils::SSL

  before do
    skip 'requires native Ruby OpenSSL and OpenSSL 3.5+' unless RUBY_ENGINE == 'ruby' && OpenSSL::OPENSSL_VERSION_NUMBER >= 0x30500000
  end

  [true, false].each do |provided_subordinate_crl|
    it "imports a full ML-DSA hierarchy with #{provided_subordinate_crl ? 'a supplied' : 'an automatically created'} subordinate CRL" do
      Dir.mktmpdir do |dir|
        with_temp_dirs(dir) do |config|
          File.open(config, 'a') { |file| file.puts "\n[main]\nconfdir = #{dir}\nca_ttl = 1h" }
          root_key = OpenSSL::PKey.generate_key('ML-DSA-44')
          root = create_cert(root_key, 'Root')
          ca_key = OpenSSL::PKey.generate_key('ML-DSA-44')
          ca = create_cert(ca_key, 'Subordinate', root_key, root)
          server_key = OpenSSL::PKey.generate_key('ML-DSA-44')
          private_path = "#{dir}/ssl/private_keys/localhost.pem"
          public_path = "#{dir}/ssl/public_keys/localhost.pem"
          FileUtils.mkdir_p([File.dirname(private_path), File.dirname(public_path)])
          File.open(private_path, 'w', 0o640) { |file| file.write(server_key.private_to_pem) }
          File.write(public_path, server_key.public_to_pem)
          File.write("#{dir}/ca.pem", ca.to_pem + root.to_pem)
          File.write("#{dir}/key.pem", ca_key.private_to_pem)
          crls = provided_subordinate_crl ? create_crl(ca, ca_key).to_pem : ''
          File.write("#{dir}/crls.pem", crls + create_crl(root, root_key).to_pem)
          logger = Puppetserver::Ca::Logger.new(:info, StringIO.new, StringIO.new)
          action = Puppetserver::Ca::Action::Import.new(logger)
          expect(action.run({ 'config' => config, 'certname' => 'localhost', 'subject-alt-names' => 'localhost',
                              'cert-bundle' => "#{dir}/ca.pem", 'private-key' => "#{dir}/key.pem", 'crl-chain' => "#{dir}/crls.pem" })).to eq(0)
          cert = OpenSSL::X509::Certificate.new(File.read("#{dir}/ssl/certs/localhost.pem"))
          expect(cert.signature_algorithm).to eq('ML-DSA-44')
          expect(cert.check_private_key(server_key)).to be(true)
          expect(cert.issuer.to_der).to eq(ca.subject.to_der)
          expect(cert.extensions.find { |ext| ext.oid == 'keyUsage' }.value).to eq('Digital Signature')
          expect(cert.extensions.find { |ext| ext.oid == 'subjectAltName' }.value.split(', ').uniq).to eq(['DNS:localhost'])
          expect(OpenSSL::PKey.read(File.read("#{dir}/ca/ca_key.pem")).public_to_der).to eq(ca_key.public_to_der)
          expect(OpenSSL::PKey.read(File.read(public_path)).public_to_der).to eq(server_key.public_to_der)
          expect(File.stat("#{dir}/ca/ca_key.pem").mode & 0o777).to eq(0o640)
          expect(File.stat(private_path).mode & 0o777).to eq(0o640)
          store = OpenSSL::X509::Store.new
          [root, ca].each { |issuer| store.add_cert(issuer) }
          store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
          imported_crls = File.read("#{dir}/ca/ca_crl.pem").scan(/-----BEGIN X509 CRL-----.*?-----END X509 CRL-----/m).map { |pem| OpenSSL::X509::CRL.new(pem) }
          imported_crls.each { |crl| store.add_crl(crl) }
          expect(store.verify(cert)).to be(true)
          expect(imported_crls.map(&:signature_algorithm)).to all(eq('ML-DSA-44'))
          csr = Puppetserver::Ca::Host.new(OpenSSL::Digest::SHA256.new).create_csr(name: 'localhost', key: server_key)
          expect(csr.verify(server_key)).to be(true)
          crl = imported_crls.find { |item| item.issuer == ca.subject }
          Puppetserver::Ca::Action::Prune.new(logger).update_pruned_CRL(crl, ca_key)
          expect(crl.verify(ca.public_key)).to be(true)
          expect(crl.signature_algorithm).to eq('ML-DSA-44')
        end
      end
    end
  end
end
