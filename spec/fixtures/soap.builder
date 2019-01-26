xml.instruct!

xml.Envelope do
  xml.Header do
    xml.Security do
      encrypt_key_for(xml: xml, id: key_id)
      xml.BinarySecurityToken ''
    end
  end
  xml.Body Id: id  do
    encrypt_data_for xml: xml, key_info: key_info do |xml|
      xml.EncryptMe do
        xml.Secret "secret"
      end
    end
  end
end
