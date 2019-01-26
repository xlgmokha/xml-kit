# frozen_string_literal: true

module Xml
  module Kit
    # {include:file:spec/xml/kit/decryption_spec.rb}
    class Decryption
      # The list of private keys to use to attempt to decrypt the document.
      attr_reader :cipher_registry, :private_keys

      def initialize(private_keys:, cipher_registry: ::Xml::Kit::Crypto)
        @private_keys = private_keys
        @cipher_registry = cipher_registry
      end

      # Decrypts an EncryptedData section of an XML document.
      #
      # @param data [Hash] the XML document converted to a [Hash] using Hash.from_xml.
      def decrypt(data)
        ::Xml::Kit.deprecate(
          'decrypt is deprecated. Use decrypt_xml or decrypt_hash instead.'
        )
        decrypt_hash(data)
      end

      # Decrypts an EncryptedData section of an XML document.
      #
      # @param raw_xml [String] the XML document as a string.
      def decrypt_xml(raw_xml)
        decrypt_hash(Hash.from_xml(raw_xml))
      end

      # Decrypts an EncryptedData section of an XML document.
      #
      # @param hash [Hash] the XML document converted to a [Hash] using Hash.from_xml.
      def decrypt_hash(hash)
        data = hash['EncryptedData']
        to_plaintext(
          Base64.decode64(data['CipherData']['CipherValue']),
          symmetric_key_from(data['KeyInfo']['EncryptedKey']),
          data['EncryptionMethod']['Algorithm']
        )
      end

      # Decrypts an EncryptedData Nokogiri::XML::Element.
      #
      # @param node [Nokogiri::XML::Element.] the XML node to decrypt.
      def decrypt_node(node)
        return node unless !node.nil? && node.name == 'EncryptedData'

        node.parent.replace(decrypt_xml(node.to_s))[0]
      end

      private

      def symmetric_key_from(encrypted_key, attempts = private_keys.count)
        cipher, algorithm = cipher_and_algorithm_from(encrypted_key)
        private_keys.each do |private_key|
          begin
            attempts -= 1
            return to_plaintext(cipher, private_key, algorithm)
          rescue OpenSSL::PKey::RSAError
            raise if attempts.zero?
          end
        end
        raise DecryptionError, private_keys
      end

      def to_plaintext(cipher_text, private_key, algorithm)
        cipher_registry.cipher_for(algorithm, private_key).decrypt(cipher_text)
      end

      def cipher_and_algorithm_from(encrypted_key)
        [
          Base64.decode64(encrypted_key['CipherData']['CipherValue']),
          encrypted_key['EncryptionMethod']['Algorithm']
        ]
      end
    end
  end
end
