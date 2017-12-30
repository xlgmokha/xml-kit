xml.instruct!
xml.Item ID: id do
  signature_for reference_id: id, xml: xml
  xml.Encrypted do
    encryption_for xml: xml do |xml|
      xml.EncryptMe do
        xml.Secret "secret"
      end
    end
  end
end
