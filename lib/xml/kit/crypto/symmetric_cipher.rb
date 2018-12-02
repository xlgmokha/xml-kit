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

        def initialize(algorithm, key = nil, padding = nil)
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
          default_decrypt(
            cipher_text[0...cipher.iv_len],
            cipher_text[cipher.iv_len..-1]
          )
        end

        protected

        def default_decrypt(initialization_vector, data)
          cipher.decrypt
          cipher.padding = padding unless padding.nil?
          cipher.key = @key
          cipher.iv = initialization_vector
          cipher.update(data) << cipher.final
        end

        private

        def cipher
          @cipher ||= OpenSSL::Cipher.new(ALGORITHMS[algorithm])
        end
      end
    end
  end
end
