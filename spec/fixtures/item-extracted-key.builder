xml.instruct!
xml.Item ID: id, xmlns: 'https://www.example.org/item#' do
  signature_for reference_id: id, xml: xml
  xml.Encrypted xmlns: 'https://www.example.org/item#' do
    key_info = ::Xml::Kit::KeyInfo.new
    key_info.retrieval_method.uri = "#EK"
    encrypt_data_for(xml: xml, key_info: key_info) do |xml|
      xml.EncryptMe do
        xml.Secret "secret"
      end
    end
  end
end
