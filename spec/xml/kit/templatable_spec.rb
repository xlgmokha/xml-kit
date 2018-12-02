# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Templatable do
  class Item
    include ::Xml::Kit::Templatable
  end
  subject { Item.new }

  describe '#encryption_for' do
    context 'when encrypting xml' do
      before do
        subject.encrypt = true
        subject.encryption_certificate = ::Xml::Kit::KeyPair.generate(use: :encryption).certificate
      end

      let(:result) do
        subject.encryption_for(xml: ::Builder::XmlMarkup.new) do |xml|
          xml.HelloWorld Time.now.iso8601
        end
      end
      let(:xml_hash) { Hash.from_xml(result) }

      specify { expect(result).to include('EncryptedData') }
      specify { expect(xml_hash['EncryptedData']).to be_present }
      specify { expect(xml_hash['EncryptedData']['EncryptionMethod']).to be_present }
    end

    context 'when disabled' do
      before do
        subject.encrypt = false
        subject.encryption_certificate = ::Xml::Kit::KeyPair.generate(use: :encryption).certificate
      end

      let(:result) do
        subject.encryption_for(xml: ::Builder::XmlMarkup.new) do |xml|
          xml.HelloWorld Time.now.iso8601
        end
      end

      specify { expect(result).to include('HelloWorld') }
      specify { expect(result).not_to include('EncryptedData') }
      specify { expect(Hash.from_xml(result)['HelloWorld']).to be_present }
    end

    context 'when a cert is missing' do
      before do
        subject.encrypt = true
        subject.encryption_certificate = nil
      end

      let(:result) do
        subject.encryption_for(xml: ::Builder::XmlMarkup.new) do |xml|
          xml.HelloWorld Time.now.iso8601
        end
      end

      specify { expect(result).to include('HelloWorld') }
      specify { expect(result).not_to include('EncryptedData') }
      specify { expect(Hash.from_xml(result)['HelloWorld']).to be_present }
    end
  end

  describe '#encrypt_with' do
    before do
      subject.encrypt_with(key_pair.certificate)
    end

    let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :encryption) }
    let(:result) do
      subject.encryption_for(xml: ::Builder::XmlMarkup.new) do |xml|
        xml.HelloWorld Time.now.iso8601
      end
    end

    specify { expect(result).to include('EncryptedData') }
    specify { expect(Hash.from_xml(result)['EncryptedData']).to be_present }
    specify { expect(Hash.from_xml(result)['EncryptedData']['EncryptionMethod']).to be_present }
  end

  describe '#to_xml' do
    context 'when generating a signed document' do
      let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :signing) }

      before do
        subject.sign_with(key_pair)
      end

      it 'produces a valid signature' do
        result = subject.to_xml
        node = Nokogiri::XML(result).at_xpath('//ds:Signature', ds: ::Xml::Kit::Namespaces::XMLDSIG)
        dsignature = Xmldsig::Signature.new(node, 'ID=$uri or @Id')
        expect(dsignature).to be_valid(key_pair.certificate.x509)
        expect(dsignature.errors).to be_empty
      end
    end
  end
end
