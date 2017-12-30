RSpec.describe Xml::Kit::Encryption do
  subject { described_class.new(xml, public_key) }
  let(:public_key) { key_pair.public_key }
  let(:key_pair) { Xml::Kit::KeyPair.generate(use: :encryption) }
  let(:xml) do
    xml = ::Builder::XmlMarkup.new
    xml.HellWorld do
      xml.Now Time.now.iso8601
    end
    xml.target!
  end

  describe "#to_xml" do
    let(:decryptor) { Xml::Kit::Decryption.new(private_keys: [key_pair.private_key]) }

    it 'generates an encrypted xml using AES-256-CBC' do
      result = subject.to_xml
      expect(decryptor.decrypt_xml(result)).to eql(xml)
    end
  end
end
