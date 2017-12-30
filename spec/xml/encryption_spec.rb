RSpec.describe Xml::Kit::Encryption do
  describe "#to_xml" do
    [
      'AES-128-CBC',
      'AES-192-CBC',
      'AES-256-CBC',
    ].each do |algorithm|
      describe algorithm do
        subject { described_class.new(xml, public_key, algorithm) }
        let(:key_pair) { Xml::Kit::KeyPair.generate(use: :encryption, algorithm: algorithm) }
        let(:decryptor) { Xml::Kit::Decryption.new(private_keys: [key_pair.private_key]) }
        let(:public_key) { key_pair.public_key }
        let(:xml) do
          xml = ::Builder::XmlMarkup.new
          xml.HellWorld do
            xml.Now Time.now.iso8601
          end
          xml.target!
        end

        it "generates an encrypted xml" do
          expect(decryptor.decrypt_xml(subject.to_xml)).to eql(xml)
        end
      end
    end
  end
end
