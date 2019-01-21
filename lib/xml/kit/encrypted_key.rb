require 'xml/kit/templatable'

module Xml
  module Kit
    class EncryptedKey
      include ::Xml::Kit::Templatable

      attr_reader :id, :algorithm
      attr_reader :public_key, :key

      def initialize(id:, public_key:, key:, algorithm: ::Xml::Kit::Crypto::RsaCipher::ALGORITHM)
        @id = id
        @algorithm = algorithm
        @public_key = public_key
        @key = key
      end

      def cipher_value
        Base64.strict_encode64(public_key.public_encrypt(key))
      end
    end
  end
end
