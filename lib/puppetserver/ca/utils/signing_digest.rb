module Puppetserver
  module Ca
    module Utils
      class SigningDigest

        attr_reader :errors, :digest

        def self.mldsa44?(key)
          return false unless key.respond_to?(:public_to_der)

          # Ruby OpenSSL 4.0.2 cannot identify ML-DSA through PKey#oid.
          OpenSSL::ASN1.decode(key.public_to_der).value[0].value[0].oid == '2.16.840.1.101.3.4.3.17'
        end

        def self.for_key(key, digest)
          mldsa44?(key) ? nil : digest
        end

        def initialize
          @errors = []
          if OpenSSL::Digest.const_defined?('SHA256')
            @digest = OpenSSL::Digest::SHA256.new
          elsif OpenSSL::Digest.const_defined?('SHA1')
            @digest = OpenSSL::Digest::SHA1.new
          elsif OpenSSL::Digest.const_defined?('SHA512')
            @digest = OpenSSL::Digest::SHA512.new
          elsif OpenSSL::Digest.const_defined?('SHA384')
            @digest = OpenSSL::Digest::SHA384.new
          elsif OpenSSL::Digest.const_defined?('SHA224')
            @digest = OpenSSL::Digest::SHA224.new
          else
            @errors << "Error: No FIPS 140-2 compliant digest algorithm in OpenSSL::Digest"
          end
        end
      end
    end
  end
end
