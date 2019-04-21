xml.instruct!

xml.Envelope do
  xml.Header do
    xml.Security do
      encrypt_key_for(xml: xml, id: key_id) do |xml|
        xml.KeyInfo do
          xml.x509Data do
            xml.X509IssuerSerial do
              xml.X509IssuerName "blah"
              xml.X509IssuerNumber 1
            end
          end
        end
      end
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
