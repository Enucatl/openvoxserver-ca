require 'spec_helper'
require 'utils/ssl'
require 'shared_examples/setup'

require 'tmpdir'
require 'fileutils'
require 'puppetserver/ca/action/setup'
require 'puppetserver/ca/logger'
require 'puppetserver/ca/utils/signing_digest'
require 'puppetserver/ca/host'

RSpec.describe Puppetserver::Ca::Action::Setup do
  include Utils::SSL

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }
  let(:logger) { Puppetserver::Ca::Logger.new(:info, stdout, stderr) }
  let(:usage) { /.*Usage:.* puppetserver ca setup.*Display this command-specific help output.*/m }

  subject { Puppetserver::Ca::Action::Setup.new(logger) }

  it 'defaults to RSA and accepts an explicit key type' do
    [[], ['--key-type', 'rsa'], ['--key-type', 'mldsa44']].each do |args|
      input, exit_code = subject.parse(args.dup)
      expect(exit_code).to be_nil
      expect(input['key-type']).to eq(args.last || 'rsa')
    end
  end

  it 'rejects unsupported and missing key types' do
    [['--key-type', 'mldsa65'], ['--key-type']].each do |args|
      _, exit_code = subject.parse(args)
      expect(exit_code).to eq(1)
    end
    expect(stderr.string).to include('--key-type')
  end

  [nil, 'rsa'].each do |key_type|
    it "generates RSA keys #{key_type ? 'with an explicit flag' : 'by default despite agent configuration'}" do
      Dir.mktmpdir do |dir|
        with_temp_dirs(dir) do |config|
          File.open(config, 'a') { |file| file.puts "\n[main]\nconfdir = #{dir}\nkey_type = mldsa44" }
          args = ['--config', config, '--certname', 'localhost']
          args += ['--key-type', key_type] if key_type
          input, exit_code = subject.parse(args)
          expect(exit_code).to be_nil
          expect(subject.run(input)).to eq(0)
          %w[ca/root_key.pem ca/ca_key.pem ssl/private_keys/localhost.pem].each do |path|
            expect(OpenSSL::PKey.read(File.read("#{dir}/#{path}"))).to be_a(OpenSSL::PKey::RSA)
          end
        end
      end
    end
  end

  it 'reports unavailable ML-DSA without writing PKI files' do
    Dir.mktmpdir do |dir|
      with_temp_dirs(dir) do |config|
        allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-44').and_raise(OpenSSL::PKey::PKeyError, 'unsupported algorithm')
        input, exit_code = subject.parse(['--config', config, '--key-type', 'mldsa44'])
        expect(exit_code).to be_nil
        expect(subject.run(input)).to eq(1)
        expect(stderr.string).to include('Unable to generate mldsa44 PKI', 'unsupported algorithm')
        expect(Dir.glob("#{dir}/**/*.pem")).to be_empty
      end
    end
  end

  it 'reports missing ML-DSA key-generation API without writing PKI files' do
    Dir.mktmpdir do |dir|
      with_temp_dirs(dir) do |config|
        allow(OpenSSL::PKey).to receive(:respond_to?).and_call_original
        allow(OpenSSL::PKey).to receive(:respond_to?).with(:generate_key).and_return(false)
        input, = subject.parse(['--config', config, '--key-type', 'mldsa44'])
        expect(subject.run(input)).to eq(1)
        expect(stderr.string).to include('ML-DSA-44 requires native Ruby OpenSSL')
        expect(Dir.glob("#{dir}/**/*.pem")).to be_empty
      end
    end
  end

  it 'prints the help output & returns 1 if invalid flags are given' do
    _, exit_code = subject.parse(['--hello'])
    expect(stderr.string).to match(/Error.*--hello/m)
    expect(stderr.string).to match(usage)
    expect(exit_code).to eq(1)
  end

  it 'does not print the help output if called correctly' do
    Dir.mktmpdir do |tmpdir|
      with_temp_dirs tmpdir do |conf|
        exit_code = subject.run({ 'config' => conf,
                                  'subject-alt-names' => '',
                                  'ca-name' => '',
                                  'root-ca-name' => '',
                                  'certname' => '' })
        puts stderr.string
        expect(stderr.string).to be_empty
        expect(stdout.string.strip).to eq("Generation succeeded. Find your files in #{tmpdir}/ca")
        expect(exit_code).to eq(0)
      end
    end
  end

  include_examples 'properly sets up ca and ssl dir', Puppetserver::Ca::Action::Setup

  describe 'command line name overrides' do
    it 'uses the ca_name and root_ca_name as specified on the command line' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |conf|
          exit_code = subject.run({ 'config' => conf,
                                    'subject-alt-names' => '',
                                    'ca-name' => 'Foo CA',
                                    'root-ca-name' => 'Foo Root CA',
                                    'certname' => '' })
          expect(exit_code).to eq(0)
          ca_cert_file = File.join(tmpdir, 'ca', 'ca_crt.pem')
          expect(File.exist?(ca_cert_file)).to be true
          ca_cert = OpenSSL::X509::Certificate.new(File.read(ca_cert_file))
          expect(ca_cert.subject.to_s).to include('Foo CA')
          expect(ca_cert.issuer.to_s).to include('Foo Root CA')
        end
      end
    end

    it 'uses the default ca_name if none specified' do
      Dir.mktmpdir do |tmpdir|
        with_temp_dirs tmpdir do |conf|
          exit_code = subject.run({ 'config' => conf,
                                    'subject-alt-names' => '',
                                    'ca-name' => '',
                                    'root-ca-name' => '',
                                    'certname' => '' })
          expect(exit_code).to eq(0)
          ca_cert_file = File.join(tmpdir, 'ca', 'ca_crt.pem')
          expect(File.exist?(ca_cert_file)).to be true
          ca_cert = OpenSSL::X509::Certificate.new(File.read(ca_cert_file))
          expect(ca_cert.subject.to_s).to include('Puppet CA')
          expect(ca_cert.issuer.to_s).to match(/Puppet Root CA: ([0-9a-f]{14})/)
        end
      end
    end
  end
end
