RSpec.describe Xml::Kit::ExternalKeyInfo do
  describe '#to_xml' do
    subject { described_class.new(uri: uri, type: type) }

    let(:uri) { '#EK' }
    let(:type) { 'http://www.w3.org/2001/04/xmlenc#EncryptedKey' }
    let(:result) { Hash.from_xml(subject.to_xml) }

    specify { expect(result['KeyInfo']).to be_present }
    specify { expect(result['KeyInfo']['RetrievalMethod']).to be_present }
    specify { expect(result['KeyInfo']['RetrievalMethod']['xmlns']).to eql(::Xml::Kit::Namespaces::XMLDSIG) }
    specify { expect(result['KeyInfo']['RetrievalMethod']['URI']).to eql(uri) }
    specify { expect(result['KeyInfo']['RetrievalMethod']['Type']).to eql(type) }
    specify { expect(result['KeyInfo']['EncryptedKey']).to be_nil }
  end
end
