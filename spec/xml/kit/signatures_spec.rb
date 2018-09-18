# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Signatures do
  let(:reference_id) { Xml::Kit::Id.generate }
  let(:options) { { 'xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol', 'xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion', ID: reference_id } }
  let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :signing) }

  it 'generates a signature' do
    signed_xml = described_class.sign(key_pair: key_pair) do |xml, signature|
      xml.tag!('samlp:AuthnRequest', options) do
        signature.template(reference_id)
        xml.tag!('saml:Issuer', 'MyEntityID')
      end
    end
    result = Hash.from_xml(signed_xml)

    signature = result['AuthnRequest']['Signature']
    expect(signature['xmlns']).to eql('http://www.w3.org/2000/09/xmldsig#')
    expect(signature['SignedInfo']['CanonicalizationMethod']['Algorithm']).to eql('http://www.w3.org/2001/10/xml-exc-c14n#')
    expect(signature['SignedInfo']['SignatureMethod']['Algorithm']).to eql('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')

    expect(signature['SignedInfo']['Reference']['URI']).to eql("##{reference_id}")
    expect(signature['SignedInfo']['Reference']['Transforms']['Transform']).to match_array([
      { 'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#enveloped-signature' },
      { 'Algorithm' => 'http://www.w3.org/2001/10/xml-exc-c14n#' }
    ])
    expect(signature['SignedInfo']['Reference']['DigestMethod']['Algorithm']).to eql('http://www.w3.org/2001/04/xmlenc#sha256')
    expected_certificate = key_pair.certificate.stripped
    expect(signature['KeyInfo']['X509Data']['X509Certificate']).to eql(expected_certificate)
    expect(signature['SignedInfo']['Reference']['DigestValue']).to be_present
    expect(signature['SignatureValue']).to be_present
    expect(OpenSSL::X509::Certificate.new(Base64.decode64(signature['KeyInfo']['X509Data']['X509Certificate']))).to be_present
  end

  it 'does not add a signature' do
    signed_xml = described_class.sign(key_pair: nil) do |xml, signature|
      xml.AuthnRequest do
        signature.template(reference_id)
        xml.Issuer 'MyEntityID'
      end
    end
    result = Hash.from_xml(signed_xml)
    expect(result['AuthnRequest']).to be_present
    expect(result['AuthnRequest']['Signature']).to be_nil
  end

  it 'produces a valid signature' do
    result = described_class.sign(key_pair: key_pair) do |xml, signature|
      xml.tag!('saml:Assertion', options) do
        signature.template(reference_id)
        xml.tag! 'saml:Subject' do
          xml.NameID Format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        end
      end
    end

    node = Nokogiri::XML(result).at_xpath('//ds:Signature', ds: ::Xml::Kit::Namespaces::XMLDSIG)
    dsignature = Xmldsig::Signature.new(node, 'ID=$uri or @Id')
    expect(dsignature).to be_valid(key_pair.certificate.x509)
    expect(dsignature.errors).to be_empty
  end
end
