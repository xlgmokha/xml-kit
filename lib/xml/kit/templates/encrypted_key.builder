# frozen_string_literal: true

xml.EncryptedKey Id: id, xmlns: ::Xml::Kit::Namespaces::XMLENC do
  xml.EncryptionMethod Algorithm: asymmetric_cipher.algorithm
  render(key_info, xml: xml) if key_info
  xml.CipherData do
    xml.CipherValue cipher_value
  end
end
