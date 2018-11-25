# frozen_string_literal: true

module Xml
  module Kit
    module Crypto
      class SymmetricCipher
        DEFAULT_ALGORITHM = "#{::Xml::Kit::Namespaces::XMLENC}aes256-cbc".freeze
        TRIPLE_DES_ALGORITHM = "#{::Xml::Kit::Namespaces::XMLENC}tripledes-cbc".freeze
        ALGORITHMS = {
          TRIPLE_DES_ALGORITHM => 'DES-EDE3-CBC',
          "#{::Xml::Kit::Namespaces::XMLENC}aes128-cbc" => 'AES-128-CBC',
          "#{::Xml::Kit::Namespaces::XMLENC}aes192-cbc" => 'AES-192-CBC',
          DEFAULT_ALGORITHM => 'AES-256-CBC',
        }.freeze

        attr_reader :key

        def initialize(algorithm, key = nil)
          @algorithm = algorithm
          @key = key || cipher.random_key
        end

        def self.matches?(algorithm)
          ALGORITHMS[algorithm]
        end

        def encrypt(plain_text)
          cipher.encrypt
          cipher.key = @key
          cipher.random_iv + cipher.update(plain_text) + cipher.final
        end

        def decrypt(cipher_text)
          cipher.decrypt
          cipher.key = @key
          cipher.iv = cipher_text[0...cipher.iv_len]

          return decrypt_des(cipher, cipher_text) if triple_des?

          decrypt_aes(cipher, cipher_text)
        end

        private

        def decrypt_des(cipher, cipher_text)
          cipher.update(cipher_text[cipher.iv_len..-1]) << cipher.final
        end

        def decrypt_aes(cipher, cipher_text)
          cipher.padding = 0
          result = cipher.update(cipher_text[cipher.iv_len..-1]) << cipher.final
          result[0...-result.last.unpack('c').first]
        end

        def cipher
          @cipher ||= OpenSSL::Cipher.new(ALGORITHMS[@algorithm])
        end

        def triple_des?
          @algorithm == TRIPLE_DES_ALGORITHM
        end
      end
    end
  end
end
