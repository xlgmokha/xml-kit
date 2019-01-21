xml.instruct!
xml.Item ID: id, xmlns: 'https://www.example.org/item#' do
  signature_for reference_id: id, xml: xml
  xml.Encrypted xmlns: 'https://www.example.org/item#' do
    encryption_for xml: xml do |xml|
      xml.EncryptMe do
        xml.Secret "secret"
      end
    end
  end
end
