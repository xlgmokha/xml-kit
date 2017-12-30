xml.Signature "xmlns" => ::Xml::Kit::Namespaces::XMLDSIG do
  xml.SignedInfo do
    xml.CanonicalizationMethod Algorithm: ::Xml::Kit::Namespaces::CANONICALIZATION
    xml.SignatureMethod Algorithm: signature_method
    xml.Reference URI: "##{reference_id}" do
      xml.Transforms do
        xml.Transform Algorithm: "#{::Xml::Kit::Namespaces::XMLDSIG}enveloped-signature"
        xml.Transform Algorithm: ::Xml::Kit::Namespaces::CANONICALIZATION
      end
      xml.DigestMethod Algorithm: digest_method
      xml.DigestValue ""
    end
  end
  xml.SignatureValue ""
  xml.KeyInfo do
    xml.X509Data do
      xml.X509Certificate certificate.stripped
    end
  end
end
