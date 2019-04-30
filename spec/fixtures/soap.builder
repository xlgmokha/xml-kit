xml.instruct!

xml.Envelope do
  xml.Header do
    xml.Security do
      encrypt_key_for(xml: xml, id: key_id, key_info: header_key_info)
      xml.BinarySecurityToken ''
    end
  end
  xml.Body Id: id  do
    encrypt_data_for xml: xml, key_info: data_key_info do |xml|
      xml.EncryptMe do
        xml.Secret "secret"
      end
    end
  end
end
