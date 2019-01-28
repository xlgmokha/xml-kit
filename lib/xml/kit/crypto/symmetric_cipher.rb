# frozen_string_literal: true

module Xml
  module Kit
    module Crypto
      class SymmetricCipher
        DEFAULT_ALGORITHM = "#{::Xml::Kit::Namespaces::XMLENC}aes256-cbc".freeze
        ALGORITHMS = {
          "#{::Xml::Kit::Namespaces::XMLENC}tripledes-cbc" => 'DES-EDE3-CBC',
          "#{::Xml::Kit::Namespaces::XMLENC}aes128-cbc" => 'AES-128-CBC',
          "#{::Xml::Kit::Namespaces::XMLENC}aes192-cbc" => 'AES-192-CBC',
          "#{::Xml::Kit::Namespaces::XMLENC}aes256-cbc" => 'AES-256-CBC',
        }.freeze

        attr_reader :algorithm, :key, :padding

        def initialize(algorithm = DEFAULT_ALGORITHM, key = nil, padding = nil)
          @algorithm = algorithm
          @key = key || cipher.random_key
          @padding = padding
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
          bytes = cipher_text.bytes
          result = default_decrypt(
            bytes[0...cipher.iv_len],
            bytes[cipher.iv_len..-1]
          )
          return result if padding.nil?

          padding_size = result.bytes.last
          result[0...-padding_size]
        end

        def to_s
          algorithm
        end

        protected

        def default_decrypt(initialization_vector, data)
          cipher.decrypt
          apply_padding_to(cipher)
          cipher.key = @key
          cipher.iv = initialization_vector.pack('c*')
          cipher.update(data.pack('c*')) << cipher.final
        end

        private

        def cipher
          @cipher ||= OpenSSL::Cipher.new(ALGORITHMS[algorithm])
        end

        def apply_padding_to(cipher)
          cipher.padding = padding unless padding.nil?
        end
      end
    end
  end
end
