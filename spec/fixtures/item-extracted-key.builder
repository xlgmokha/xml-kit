xml.instruct!
xml.Item ID: id, xmlns: 'https://www.example.org/item#' do
  signature_for reference_id: id, xml: xml
  xml.Encrypted xmlns: 'https://www.example.org/item#' do
    encryption_for(xml: xml, key_info: ::Xml::Kit::ExternalKeyInfo.new(uri: "#EK")) do |xml|
      xml.EncryptMe do
        xml.Secret "secret"
      end
    end
  end
end
