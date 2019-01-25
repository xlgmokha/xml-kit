xml.instruct!

xml.Envelope xmlns: "http://schemas.xmlsoap.org/soap/envelope/" do
  xml.Header do
    xml.Security mustUnderstand: '1' do
      encrypt_key_for(xml: xml, id: key_id, public_key: encryption_key_pair.public_key, key: symmetric_key)
      xml.BinarySecurityToken ''
    end
  end
  xml.Body xmlns: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd', Id: id  do
    encrypt_data_for xml: xml, key_info: body_key_info do |xml|
      xml.EncryptMe do
        xml.Secret "secret"
      end
    end
  end
end
