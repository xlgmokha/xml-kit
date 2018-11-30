# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Crypto::SymmetricCipher do
  let(:key_size) do
    hash = Hash.new(32 / 2)
    hash['aes128-cbc'] = 16 / 2
    hash['aes192-cbc'] = 24 / 2
    hash['tripledes-cbc'] = 24 / 2
    hash
  end

  [
    'tripledes-cbc',
    'aes128-cbc',
    'aes192-cbc',
    'aes256-cbc',
  ].each do |algorithm|
    describe algorithm do
      subject { described_class.new("#{::Xml::Kit::Namespaces::XMLENC}#{algorithm}", key) }

      let(:key) { SecureRandom.hex(key_size[algorithm]) }
      let(:uuid) { SecureRandom.uuid }

      specify { expect(subject.decrypt(subject.encrypt(uuid))).to eql(uuid) }
    end
  end

  describe "decrypting something encrypted with the OpenSSL CLI" do
    subject { described_class.new("#{::Xml::Kit::Namespaces::XMLENC}#{algorithm}", key) }

    let(:encrypted_file) { Tempfile.new('aes-128-cbc').path }
    let(:original_file) { __FILE__ }
    let(:decrypted_file) { Tempfile.new('aes-128-cbc-decrypted').path }
    let(:algorithm) { 'aes128-cbc' }
    let(:key) { SecureRandom.hex(8) }
    let(:iv) { SecureRandom.hex(8) }

    before do
      raise 'heck' unless system("openssl enc -aes-128-cbc -p -A -nosalt -in #{original_file} -out #{encrypted_file} -K #{key} -iv #{iv}")
      raise 'heck' unless system("openssl enc -aes-128-cbc -p -d -nosalt -in #{encrypted_file} -out #{decrypted_file} -K #{key} -iv #{iv}")
    end

    specify do
      expect(subject.decrypt(IO.read(encrypted_file))).to eql(IO.read(decrypted_file))
    end
  end

  describe "when decrypting with the OpenSSL CLI" do
    subject { described_class.new("#{::Xml::Kit::Namespaces::XMLENC}#{algorithm}", key) }

    let(:encrypted_file) { Tempfile.new('aes-128-cbc').path }
    let(:original_file) { __FILE__ }
    let(:decrypted_file) { Tempfile.new('aes-128-cbc-decrypted').path }
    let(:algorithm) { 'aes128-cbc' }
    let(:key) { SecureRandom.hex(8) }
    let(:iv) { SecureRandom.hex(8) }
    let(:original_content) { IO.read(original_file) }

    before do
      IO.write(encrypted_file, subject.encrypt(IO.read(original_file)))
      system("openssl enc -aes-128-cbc -p -d -nosalt -in #{encrypted_file} -out #{decrypted_file} -K #{key.unpack("H*")[0]} -iv #{iv.unpack("H*")[0]}")
    end

    specify { expect(IO.read(decrypted_file)).to end_with(original_content) }
  end
end
