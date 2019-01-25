# frozen_string_literal: true

module Xml
  module Kit
    module Crypto
      class RsaCipher
        ALGORITHM = "#{::Xml::Kit::Namespaces::XMLENC}rsa-1_5".freeze
        attr_reader :algorithm, :key

        def initialize(algorithm, key)
          @algorithm = algorithm
          @key = key
        end

        def self.matches?(algorithm)
          ALGORITHM == algorithm
        end

        def encrypt(plain_text)
          @key.public_encrypt(plain_text)
        end

        def decrypt(cipher_text)
          @key.private_decrypt(cipher_text)
        end
      end
    end
  end
end
