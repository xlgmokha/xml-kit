xml.KeyInfo xmlns: ::Xml::Kit::Namespaces::XMLDSIG do
  xml.KeyName key_name if key_name
  render(key_value, xml: xml) if @key_value
  xml.EncryptedKey xmlns: ::Xml::Kit::Namespaces::XMLENC do
    xml.EncryptionMethod Algorithm: algorithm
    xml.CipherData do
      xml.CipherValue cipher_value
    end
  end
end
