# frozen_string_literal: true

module Xml
  module Kit
    module Crypto
      class OaepCipher
        ALGORITHM = "#{::Xml::Kit::Namespaces::XMLENC}rsa-oaep-mgf1p".freeze
        ALGORITHMS = {
          ALGORITHM => true
        }.freeze
        attr_reader :algorithm, :key

        def initialize(algorithm, key)
          @algorithm = algorithm
          @key = key
        end

        def self.matches?(algorithm)
          ALGORITHMS[algorithm]
        end

        def encrypt(plain_text)
          @key.public_encrypt(plain_text, padding)
        end

        def decrypt(cipher_text)
          @key.private_decrypt(cipher_text, padding)
        end

        private

        def padding
          OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
        end
      end
    end
  end
end
