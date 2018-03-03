module Xml
  module Kit
    # {include:file:spec/saml/xml_decryption_spec.rb}
    class Decryption
      # The list of private keys to use to attempt to decrypt the document.
      attr_reader :private_keys

      def initialize(private_keys:)
        @private_keys = private_keys
      end

      # Decrypts an EncryptedData section of an XML document.
      #
      # @param data [Hash] the XML document converted to a [Hash] using Hash.from_xml.
      def decrypt(data)
        ::Xml::Kit.deprecate('decrypt is deprecated. Use decrypt_xml or decrypt_hash instead.')
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
        encrypted_data = hash['EncryptedData']
        symmetric_key = symmetric_key_from(encrypted_data)
        cipher_value = encrypted_data['CipherData']['CipherValue']
        cipher_text = Base64.decode64(cipher_value)
        algorithm = encrypted_data['EncryptionMethod']['Algorithm']
        to_plaintext(cipher_text, symmetric_key, algorithm)
      end

      # Decrypts an EncryptedData Nokogiri::XML::Element.
      #
      # @param node [Nokogiri::XML::Element.] the XML node to decrypt.
      def decrypt_node(node)
        return node unless !node.nil? && node.name == 'EncryptedData'

        node.parent.replace(decrypt_xml(node.to_s))[0]
      end

      private

      def symmetric_key_from(encrypted_data)
        encrypted_key = encrypted_data['KeyInfo']['EncryptedKey']
        cipher_value = encrypted_key['CipherData']['CipherValue']
        cipher_text = Base64.decode64(cipher_value)
        attempts = private_keys.count
        private_keys.each do |private_key|
          begin
            attempts -= 1
            algorithm = encrypted_key['EncryptionMethod']['Algorithm']
            return to_plaintext(cipher_text, private_key, algorithm)
          rescue OpenSSL::PKey::RSAError
            raise if attempts.zero?
          end
        end
        raise DecryptionError, private_keys
      end

      def to_plaintext(cipher_text, symmetric_key, algorithm)
        Crypto.cipher_for(algorithm, symmetric_key).decrypt(cipher_text)
      end
    end
  end
end
