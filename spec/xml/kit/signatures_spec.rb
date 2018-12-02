# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Signatures do
  let(:reference_id) { Xml::Kit::Id.generate }
  let(:options) { { 'xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol', 'xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion', ID: reference_id } }
  let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :signing) }

  context 'when a key pair is specified' do
    let(:signed_xml) do
      described_class.sign(key_pair: key_pair) do |xml, signature|
        xml.tag!('samlp:AuthnRequest', options) do
          signature.template(reference_id)
          xml.tag!('saml:Issuer', 'MyEntityID')
        end
      end
    end
    let(:result) { Hash.from_xml(signed_xml) }
    let(:signature) { result['AuthnRequest']['Signature'] }
    let(:expected_certificate) { key_pair.certificate.stripped }

    specify { expect(signature['xmlns']).to eql('http://www.w3.org/2000/09/xmldsig#') }
    specify { expect(signature['SignedInfo']['CanonicalizationMethod']['Algorithm']).to eql('http://www.w3.org/2001/10/xml-exc-c14n#') }
    specify { expect(signature['SignedInfo']['SignatureMethod']['Algorithm']).to eql('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256') }
    specify { expect(signature['SignedInfo']['Reference']['URI']).to eql("##{reference_id}") }
    specify { expect(signature['SignedInfo']['Reference']['DigestMethod']['Algorithm']).to eql('http://www.w3.org/2001/04/xmlenc#sha256') }
    specify { expect(signature['KeyInfo']['X509Data']['X509Certificate']).to eql(expected_certificate) }
    specify { expect(signature['SignedInfo']['Reference']['DigestValue']).to be_present }
    specify { expect(signature['SignatureValue']).to be_present }
    specify { expect(OpenSSL::X509::Certificate.new(Base64.decode64(signature['KeyInfo']['X509Data']['X509Certificate']))).to be_present }
    specify do
      expect(signature['SignedInfo']['Reference']['Transforms']['Transform']).to match_array([
        { 'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#enveloped-signature' },
        { 'Algorithm' => 'http://www.w3.org/2001/10/xml-exc-c14n#' }
      ])
    end
  end

  context 'when a key pair is not specified' do
    let(:signed_xml) do
      described_class.sign(key_pair: nil) do |xml, signature|
        xml.AuthnRequest do
          signature.template(reference_id)
          xml.Issuer 'MyEntityID'
        end
      end
    end
    let(:result) { Hash.from_xml(signed_xml) }

    specify { expect(result['AuthnRequest']).to be_present }
    specify { expect(result['AuthnRequest']['Signature']).to be_nil }
  end

  context 'when the signature is embedded' do
    let(:result) do
      described_class.sign(key_pair: key_pair) do |xml, signature|
        xml.tag!('saml:Assertion', options) do
          signature.template(reference_id)
          xml.tag! 'saml:Subject' do
            xml.NameID Format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
          end
        end
      end
    end

    it 'produces a valid signature' do
      node = Nokogiri::XML(result).at_xpath('//ds:Signature', ds: ::Xml::Kit::Namespaces::XMLDSIG)
      dsignature = Xmldsig::Signature.new(node, 'ID=$uri or @Id')
      expect(dsignature).to be_valid(key_pair.certificate.x509)
      expect(dsignature.errors).to be_empty
    end
  end
end
