require 'xml/kit/templatable'

module Xml
  module Kit
    class EncryptedKey
      DEFAULT_ALGORITHM = ::Xml::Kit::Crypto::RsaCipher::ALGORITHM
      include ::Xml::Kit::Templatable

      attr_reader :id, :algorithm
      attr_reader :public_key, :key
      attr_accessor :key_info

      def initialize(id:, public_key:, key:, key_info: nil, algorithm: DEFAULT_ALGORITHM)
        @id = id
        @algorithm = algorithm
        @public_key = public_key
        @key = key
        @key_info = key_info
      end

      def cipher_value
        Base64.strict_encode64(public_key.public_encrypt(key))
      end
    end
  end
end
