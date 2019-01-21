# frozen_string_literal: true

xml.EncryptedData xmlns: ::Xml::Kit::Namespaces::XMLENC do
  xml.EncryptionMethod Algorithm: symmetric_algorithm
  render key_info, xml: xml
  xml.CipherData do
    xml.CipherValue symmetric_cipher_value
  end
end
