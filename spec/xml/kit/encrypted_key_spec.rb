RSpec.describe ::Xml::Kit::EncryptedKey do
  describe "#to_xml" do
    subject { described_class.new(id: id) }
    let(:id) { ::Xml::Kit::Id.generate }
    let(:result) { Hash.from_xml(subject.to_xml) }

    before do
      puts subject.to_xml
    end

    specify { expect(result.key?('EncryptedKey')).to be_present }
    specify { expect(result['EncryptedKey']['Id']).to eql(id) }
    specify { expect(result['EncryptedKey']['xmlns']).to eql(::Xml::Kit::Namespaces::XMLENC) }
  end
end
