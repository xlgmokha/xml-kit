xml.EncryptedData xmlns: ::Xml::Kit::Namespaces::XMLENC do
  xml.EncryptionMethod Algorithm: symmetric_algorithm
  xml.KeyInfo xmlns: ::Xml::Kit::Namespaces::XMLDSIG do
    xml.EncryptedKey xmlns: ::Xml::Kit::Namespaces::XMLENC do
      xml.EncryptionMethod Algorithm: asymmetric_algorithm
      xml.CipherData do
        xml.CipherValue asymmetric_cipher_value
      end
    end
  end
  xml.CipherData do
    xml.CipherValue symmetric_cipher_value
  end
end
