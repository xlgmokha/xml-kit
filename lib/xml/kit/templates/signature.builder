# frozen_string_literal: true

xml.Signature 'xmlns' => ::Xml::Kit::Namespaces::XMLDSIG do
  xml.SignedInfo do
    xml.CanonicalizationMethod Algorithm: ::Xml::Kit::Namespaces::CANONICALIZATION
    xml.SignatureMethod Algorithm: signature_method
    reference_ids.each do |reference_id|
      xml.Reference URI: "##{reference_id}" do
        xml.Transforms do
          if enveloped?
            xml.Transform Algorithm: "#{::Xml::Kit::Namespaces::XMLDSIG}enveloped-signature"
          end
          xml.Transform Algorithm: ::Xml::Kit::Namespaces::CANONICALIZATION
        end
        xml.DigestMethod Algorithm: digest_method
        xml.DigestValue ''
      end
    end
  end
  xml.SignatureValue ''
  xml.KeyInfo do
    xml.X509Data do
      xml.X509Certificate certificate.stripped
    end
  end
end
