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
        hash = Hash.new(32/2)
        hash['aes128-cbc'] = 16/2
        hash['aes192-cbc'] = 24/2
        hash['tripledes-cbc'] = 24/2
        hash
      end
      let(:uuid) { SecureRandom.uuid }

      specify { expect(subject.decrypt(subject.encrypt(uuid))).to eql(uuid) }
    end
  end
end
