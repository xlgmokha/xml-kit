xml.EncryptedData xmlns: ::Xml::Kit::Namespaces::XMLENC do
  xml.EncryptionMethod Algorithm: symmetric_algorithm
  xml.KeyInfo xmlns: ::Xml::Kit::Namespaces::XMLDSIG do
    xml.EncryptedKey xmlns: ::Xml::Kit::Namespaces::XMLENC do
      xml.EncryptionMethod Algorithm: "#{::Xml::Kit::Namespaces::XMLENC}rsa-1_5"
      xml.CipherData do
        xml.CipherValue Base64.encode64(public_key.public_encrypt(key))
      end
    end
  end
  xml.CipherData do
    xml.CipherValue Base64.encode64(iv + encrypted)
  end
end
