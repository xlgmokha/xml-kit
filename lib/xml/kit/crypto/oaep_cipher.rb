module Xml
  module Kit
    module Crypto
      class OaepCipher
        ALGORITHMS = {
          'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' => true,
        }.freeze
        def initialize(_algorithm, key)
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
