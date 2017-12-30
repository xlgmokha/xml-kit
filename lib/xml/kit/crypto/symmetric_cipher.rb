module Xml
  module Kit
    module Crypto
      class SymmetricCipher
        DEFAULT_ALGORITHM="#{::Xml::Kit::Namespaces::XMLENC}aes256-cbc"
        ALGORITHMS = {
          "#{::Xml::Kit::Namespaces::XMLENC}tripledes-cbc" => "DES-EDE3-CBC",
          "#{::Xml::Kit::Namespaces::XMLENC}aes128-cbc" => "AES-128-CBC",
          "#{::Xml::Kit::Namespaces::XMLENC}aes192-cbc" => "AES-192-CBC",
          "#{::Xml::Kit::Namespaces::XMLENC}aes256-cbc" => "AES-256-CBC",
        }

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
          iv = cipher_text[0..cipher.iv_len-1]
          data = cipher_text[cipher.iv_len..-1]
          #cipher.padding = 0
          cipher.key = @key
          cipher.iv = iv
          cipher.update(data) + cipher.final
        end

        private

        def cipher
          @cipher ||= OpenSSL::Cipher.new(ALGORITHMS[@algorithm])
        end
      end
    end
  end
end
