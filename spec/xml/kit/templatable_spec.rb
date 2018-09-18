# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Templatable do
  class Item
    include ::Xml::Kit::Templatable
  end
  subject { Item.new }

  describe '#encryption_for' do
    it 'returns an encrypted xml' do
      subject.encrypt = true
      subject.encryption_certificate = ::Xml::Kit::KeyPair.generate(use: :encryption).certificate

      result = subject.encryption_for(xml: ::Builder::XmlMarkup.new) do |xml|
        xml.HelloWorld Time.now.iso8601
      end

      expect(result).to include('EncryptedData')
      xml_hash = Hash.from_xml(result)
      expect(xml_hash['EncryptedData']).to be_present
      expect(xml_hash['EncryptedData']['EncryptionMethod']).to be_present
    end

    it 'does not encrypt the xml, when disabled' do
      subject.encrypt = false
      subject.encryption_certificate = ::Xml::Kit::KeyPair.generate(use: :encryption).certificate

      result = subject.encryption_for(xml: ::Builder::XmlMarkup.new) do |xml|
        xml.HelloWorld Time.now.iso8601
      end

      expect(result).to include('HelloWorld')
      expect(result).not_to include('EncryptedData')
      xml_hash = Hash.from_xml(result)
      expect(xml_hash['HelloWorld']).to be_present
    end

    it 'does not encrypt the xml, when a cert is missing' do
      subject.encrypt = true
      subject.encryption_certificate = nil

      result = subject.encryption_for(xml: ::Builder::XmlMarkup.new) do |xml|
        xml.HelloWorld Time.now.iso8601
      end

      expect(result).to include('HelloWorld')
      expect(result).not_to include('EncryptedData')
      xml_hash = Hash.from_xml(result)
      expect(xml_hash['HelloWorld']).to be_present
    end
  end

  describe '#encrypt_with' do
    it 'returns an encrypted xml' do
      key_pair = ::Xml::Kit::KeyPair.generate(use: :encryption)
      subject.encrypt_with(key_pair.certificate)

      result = subject.encryption_for(xml: ::Builder::XmlMarkup.new) do |xml|
        xml.HelloWorld Time.now.iso8601
      end

      expect(result).to include('EncryptedData')
      xml_hash = Hash.from_xml(result)
      expect(xml_hash['EncryptedData']).to be_present
      expect(xml_hash['EncryptedData']['EncryptionMethod']).to be_present
    end
  end

  describe '#to_xml' do
    context 'when generating a signed document' do
      let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :signing) }

      it 'produces a valid signature' do
        subject.sign_with(key_pair)
        result = subject.to_xml
        node = Nokogiri::XML(result).at_xpath('//ds:Signature', ds: ::Xml::Kit::Namespaces::XMLDSIG)
        dsignature = Xmldsig::Signature.new(node, 'ID=$uri or @Id')
        expect(dsignature).to be_valid(key_pair.certificate.x509)
        expect(dsignature.errors).to be_empty
      end
    end
  end
end
