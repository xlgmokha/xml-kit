xml.EncryptedKey Id: id, xmlns: ::Xml::Kit::Namespaces::XMLENC do
  xml.EncryptionMethod Algorithm: algorithm
  xml.CipherData do
    xml.CipherValue cipher_value
  end
end
