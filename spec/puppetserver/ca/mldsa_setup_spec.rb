require 'spec_helper'
require 'utils/ssl'
require 'puppetserver/ca/action/setup'
require 'puppetserver/ca/logger'

RSpec.describe 'ML-DSA-44 CA setup' do
  include Utils::SSL

  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, StringIO.new, stderr) }
  let(:action) { Puppetserver::Ca::Action::Setup.new(logger) }

  before do
    skip 'requires native Ruby OpenSSL and OpenSSL 3.5+' unless RUBY_ENGINE == 'ruby' && OpenSSL::OPENSSL_VERSION_NUMBER >= 0x30500000
  end

  [false, true].each do |existing_server_key|
    it "creates a verified hierarchy with #{existing_server_key ? 'an existing' : 'a new'} ML-DSA server key" do
      Dir.mktmpdir do |dir|
        with_temp_dirs(dir) do |config|
          File.open(config, 'a') { |file| file.puts "\n[main]\nconfdir = #{dir}\nca_ttl = 1h" }
          private_path = "#{dir}/ssl/private_keys/localhost.pem"
          public_path = "#{dir}/ssl/public_keys/localhost.pem"
          if existing_server_key
            original_key = OpenSSL::PKey.generate_key('ML-DSA-44')
            FileUtils.mkdir_p([File.dirname(private_path), File.dirname(public_path)])
            File.open(private_path, 'w', 0o640) { |file| file.write(original_key.private_to_pem) }
            File.write(public_path, original_key.public_to_pem)
          end

          input, exit_code = action.parse(['--config', config, '--certname', 'localhost', '--subject-alt-names', 'DNS:alias.test,IP:127.0.0.1', '--key-type', 'mldsa44'])
          expect(exit_code).to be_nil
          expect(action.run(input)).to eq(0), stderr.string
          keys = %W[#{dir}/ca/root_key.pem #{dir}/ca/ca_key.pem #{private_path}].map do |path|
            expect(File.stat(path).mode & 0o777).to eq(0o640)
            expect(File.read(path)).to start_with('-----BEGIN PRIVATE KEY-----')
            key = OpenSSL::PKey.read(File.read(path))
            expect(Puppetserver::Ca::Utils::SigningDigest.mldsa44?(key)).to be(true)
            key
          end
          expect(keys.map(&:public_to_der).uniq.length).to eq(3)
          expect(keys.last.public_to_der).to eq(original_key.public_to_der) if existing_server_key
          expect(OpenSSL::PKey.read(File.read(public_path)).public_to_der).to eq(keys.last.public_to_der)
          expect(OpenSSL::PKey.read(File.read("#{dir}/ca/ca_pub.pem")).public_to_der).to eq(keys[1].public_to_der)

          ca, root = File.read("#{dir}/ca/ca_crt.pem").scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m).map { |pem| OpenSSL::X509::Certificate.new(pem) }
          server = OpenSSL::X509::Certificate.new(File.read("#{dir}/ssl/certs/localhost.pem"))
          [root, ca, server].zip(keys).each do |cert, key|
            expect(cert.check_private_key(key)).to be(true)
            expect(cert.signature_algorithm).to eq('ML-DSA-44')
          end
          expect(root.verify(root.public_key)).to be(true)
          expect(ca.verify(root.public_key)).to be(true)
          expect(server.verify(ca.public_key)).to be(true)
          expect(server.extensions.find { |ext| ext.oid == 'keyUsage' }.value).to eq('Digital Signature')
          expect(server.extensions.find { |ext| ext.oid == 'subjectAltName' }.value).to include('DNS:localhost', 'DNS:alias.test', 'IP Address:127.0.0.1')
          expect(server.extensions.find { |ext| ext.oid == '1.3.6.1.4.1.34380.1.3.39' }).not_to be_nil
          crls = File.read("#{dir}/ca/ca_crl.pem").scan(/-----BEGIN X509 CRL-----.*?-----END X509 CRL-----/m).map { |pem| OpenSSL::X509::CRL.new(pem) }
          store = OpenSSL::X509::Store.new
          store.add_cert(root)
          store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
          crls.zip([ca, root]).each do |crl, issuer|
            expect(crl.signature_algorithm).to eq('ML-DSA-44')
            expect(crl.verify(issuer.public_key)).to be(true)
            store.add_crl(crl)
          end
          expect(store.verify(server, [ca])).to be(true), store.error_string

          files = Dir.glob("#{dir}/**/*.pem").to_h { |path| [path, File.binread(path)] }
          expect(action.run(input)).to eq(1)
          expect(stderr.string).to include('Existing file')
          files.each { |path, content| expect(File.binread(path)).to eq(content) }
        end
      end
    end
  end

  it 'refuses an existing RSA server key without replacing it or writing CA files' do
    Dir.mktmpdir do |dir|
      with_temp_dirs(dir) do |config|
        key = OpenSSL::PKey::RSA.new(2048)
        private_path = "#{dir}/ssl/private_keys/localhost.pem"
        public_path = "#{dir}/ssl/public_keys/localhost.pem"
        FileUtils.mkdir_p([File.dirname(private_path), File.dirname(public_path)])
        File.write(private_path, key.to_pem)
        File.write(public_path, key.public_key.to_pem)
        input, = action.parse(['--config', config, '--certname', 'localhost', '--key-type', 'mldsa44'])
        expect(action.run(input)).to eq(1)
        expect(stderr.string).to include('is not ML-DSA-44; refusing to replace it')
        expect(File.read(private_path)).to eq(key.to_pem)
        expect(File.read(public_path)).to eq(key.public_key.to_pem)
        expect(Dir.glob("#{dir}/ca/*.pem")).to be_empty
      end
    end
  end
end
