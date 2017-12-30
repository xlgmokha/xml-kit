module Xml
  module Kit
    class Encryption
      DEFAULT_ALGORITHM="AES-256-CBC"
      attr_reader :public_key
      attr_reader :algorithm
      attr_reader :key, :iv, :encrypted

      def initialize(raw_xml, public_key, algorithm = DEFAULT_ALGORITHM)
        @public_key = public_key

        cipher = OpenSSL::Cipher.new(algorithm)
        cipher.encrypt
        @algorithm = ::Xml::Kit::Crypto::SimpleCipher::ALGORITHMS.key(algorithm)
        @key = cipher.random_key
        @iv = cipher.random_iv
        @encrypted = cipher.update(raw_xml) + cipher.final
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        ::Xml::Kit::Template.new(self).to_xml(xml: xml)
      end
    end
  end
end
