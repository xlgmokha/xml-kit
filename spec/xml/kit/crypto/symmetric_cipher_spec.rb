# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Crypto::SymmetricCipher do
  [
    'tripledes-cbc',
    'aes128-cbc',
    'aes192-cbc',
    'aes256-cbc',
  ].each do |algorithm|
    describe algorithm do
      subject { described_class.new("#{::Xml::Kit::Namespaces::XMLENC}#{algorithm}", key) }

      let(:key) { SecureRandom.hex(key_size[algorithm]) }
      let(:key_size) do
        hash = Hash.new(16)
        hash['aes128-cbc'] = 8
        hash['aes192-cbc'] = 12
        hash['tripledes-cbc'] = 12
        hash
      end
      let(:uuid) { SecureRandom.uuid }

      it 'encrypts/decrypts' do
        expect(subject.decrypt(subject.encrypt(uuid))).to eql(uuid)
      end
    end
  end
end
