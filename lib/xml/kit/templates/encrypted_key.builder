xml.EncryptedKey Id: id, xmlns: ::Xml::Kit::Namespaces::XMLENC do
  xml.EncryptionMethod Algorithm: algorithm
  render(key_info, xml: xml) if key_info
  xml.CipherData do
    xml.CipherValue cipher_value
  end
end
