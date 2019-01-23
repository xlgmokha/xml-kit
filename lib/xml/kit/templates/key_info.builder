# frozen_string_literal: true

xml.KeyInfo xmlns: ::Xml::Kit::Namespaces::XMLDSIG do
  xml.KeyName key_name if key_name
  render(key_value, xml: xml) if @key_value
  render(retrieval_method, xml: xml) if @retrieval_method
  if x509_data
    xml.X509Data do
      xml.X509SKI subject_key_identifier
      xml.X509Certificate ::Xml::Kit::Certificate.strip(x509_data.to_pem)
    end
  end
  render(encrypted_key, xml: xml) if encrypted_key
end
