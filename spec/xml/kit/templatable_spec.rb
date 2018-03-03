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
end
