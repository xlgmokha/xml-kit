# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Crypto::SymmetricCipher do
  def execute_shell(command)
    puts command.inspect
    raise "command failed: #{command}" unless system(command)
  end
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

  [
    ['tripledes-cbc', 192],
    ['aes128-cbc', 128],
    ['aes192-cbc', 192],
    ['aes256-cbc', 256],
  ].each do |(algorithm, bit_length)|
    describe "decrypting #{algorithm} encrypted with the OpenSSL CLI" do
      subject { described_class.new(xml_algorithm, key, 0) }

      let(:xml_algorithm) { "#{::Xml::Kit::Namespaces::XMLENC}#{algorithm}" }
      let(:openssl_algorithm) { Xml::Kit::Crypto::SymmetricCipher::ALGORITHMS[xml_algorithm] }

      let(:encrypted_file) { Tempfile.new(algorithm).path }
      let(:original_file) { Tempfile.new("#{algorithm}-original").path }
      let(:key) { SecureRandom.random_bytes(bytes_length) }
      let(:iv) { SecureRandom.random_bytes(bytes_length) }
      let(:bytes_length) { bit_length / 8 }
      let(:secret) { SecureRandom.hex }
      let(:data) { "#{iv}#{secret}".strip }

      before do
        IO.write(original_file, data, encoding: Encoding::ASCII_8BIT)
        execute_shell([
          "openssl enc -#{openssl_algorithm} -p -A -nosalt",
          "-in #{original_file}",
          "-out #{encrypted_file}",
          "-K #{key.unpack('H*')[0].upcase}",
          "-iv #{iv.unpack('H*')[0].upcase}"
        ].join(' '))
      end

      specify do
        cipher_text = IO.read(encrypted_file, encoding: Encoding::ASCII_8BIT)
        expect(subject.decrypt(cipher_text)).to include(secret)
      end
    end
  end

  describe 'when decrypting with the OpenSSL CLI' do
    subject { described_class.new("#{::Xml::Kit::Namespaces::XMLENC}aes128-cbc", key) }

    let(:encrypted_file) { Tempfile.new('aes-128-cbc').path }
    let(:original_file) { __FILE__ }
    let(:decrypted_file) { Tempfile.new('aes-128-cbc-decrypted').path }
    let(:key) { SecureRandom.hex(8) }
    let(:iv) { SecureRandom.hex(8) }
    let(:original_content) { IO.read(original_file) }

    before do
      IO.write(encrypted_file, subject.encrypt(IO.read(original_file)))
      execute_shell("openssl enc -aes-128-cbc -p -d -nosalt -in #{encrypted_file} -out #{decrypted_file} -K #{key.unpack('H*')[0]} -iv #{iv.unpack('H*')[0]}")
    end

    specify { expect(IO.read(decrypted_file)).to end_with(original_content) }
  end
end
