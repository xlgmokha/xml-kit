xml.instruct!
xml.Item ID: id, xmlns: 'https://www.example.org/item#' do
  signature_for reference_id: id, xml: xml
  xml.Encrypted xmlns: 'https://www.example.org/item#' do
    key_info = lambda do |xml|
      xml.KeyInfo xmlns: ::Xml::Kit::Namespaces::XMLDSIG do
        xml.RetrievalMethod xmlns: ::Xml::Kit::Namespaces::XMLDSIG, URI: "#EK", Type: "http://www.w3.org/2001/04/xmlenc#EncryptedKey"
      end
    end
    encryption_for(xml: xml, key_info: key_info) do |xml|
      xml.EncryptMe do
        xml.Secret "secret"
      end
    end
  end
end
