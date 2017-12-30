module Xml
  module Kit
    module Crypto
      class SimpleCipher
        ALGORITHMS = {
          "#{Namespaces::XMLENC}tripledes-cbc" => "DES-EDE3-CBC",
          "#{Namespaces::XMLENC}aes128-cbc" => "AES-128-CBC",
          "#{Namespaces::XMLENC}aes192-cbc" => "AES-192-CBC",
          "#{Namespaces::XMLENC}aes256-cbc" => "AES-256-CBC",
        }

        def initialize(algorithm, private_key)
          @algorithm = algorithm
          @private_key = private_key
        end

        def self.matches?(algorithm)
          ALGORITHMS[algorithm]
        end

        def decrypt(cipher_text)
          cipher = OpenSSL::Cipher.new(ALGORITHMS[@algorithm])
          cipher.decrypt
          iv = cipher_text[0..cipher.iv_len-1]
          data = cipher_text[cipher.iv_len..-1]
          #cipher.padding = 0
          cipher.key = @private_key
          cipher.iv = iv
          cipher.update(data) + cipher.final
        end
      end
    end
  end
end
