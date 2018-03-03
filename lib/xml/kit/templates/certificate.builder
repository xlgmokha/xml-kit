# frozen_string_literal: true

xml.KeyDescriptor use ? { use: use } : {} do
  xml.KeyInfo "xmlns": ::Xml::Kit::Namespaces::XMLDSIG do
    xml.X509Data do
      xml.X509Certificate stripped
    end
  end
end
