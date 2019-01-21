xml.instruct!

xml.Envelope xmlns: "http://schemas.xmlsoap.org/soap/envelope/" do
  xml.Header do
    xml.Security mustUnderstand: '1' do
      xml.EncryptedKey xmlns: 'http://www.w3.org/2001/04/xmlenc#', Id: key_id do
        xml.EncryptionMethod Algorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' do
          render header_key_info, xml: xml
          xml.CipherData do
            xml.CipherValue ''
          end
          xml.ReferenceList do
            xml.DataReference URI: ''
          end
        end
      end
      xml.BinarySecurityToken ''
    end
  end
  xml.Body xmlns: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd', Id: id  do
    encryption_for xml: xml, key_info: body_key_info do |xml|
      xml.EncryptMe do
        xml.Secret "secret"
      end
    end
  end
end
