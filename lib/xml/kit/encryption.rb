module Xml
  module Kit
    class Encryption
      DEFAULT_ALGORITHM="AES-256-CBC"
      attr_reader :asymmetric_algorithm
      attr_reader :asymmetric_cipher_value
      attr_reader :symmetric_algorithm
      attr_reader :symmetric_cipher_value

      def initialize(raw_xml, public_key, symmetric_algorithm = DEFAULT_ALGORITHM)
        @symmetric_algorithm = ::Xml::Kit::Crypto::SimpleCipher::ALGORITHMS.key(symmetric_algorithm)
        cipher = OpenSSL::Cipher.new(symmetric_algorithm)
        cipher.encrypt
        key = cipher.random_key
        @symmetric_cipher_value = Base64.encode64(cipher.random_iv + cipher.update(raw_xml) + cipher.final)

        @asymmetric_algorithm = "#{::Xml::Kit::Namespaces::XMLENC}rsa-1_5"
        @asymmetric_cipher_value = Base64.encode64(public_key.public_encrypt(key))
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        ::Xml::Kit::Template.new(self).to_xml(xml: xml)
      end
    end
  end
end
