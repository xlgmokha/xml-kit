# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Crypto::SymmetricCipher do
  [
    ['tripledes-cbc', 192],
    ['aes128-cbc', 128],
    ['aes192-cbc', 192],
    ['aes256-cbc', 256],
  ].each do |(algorithm, bit_length)|
    describe algorithm do
      let(:xml_algorithm) { "#{::Xml::Kit::Namespaces::XMLENC}#{algorithm}" }
      let(:openssl_algorithm) { Xml::Kit::Crypto::SymmetricCipher::ALGORITHMS[xml_algorithm].downcase }
      let(:bytes_length) { bit_length / 8 }
      let(:key) { SecureRandom.random_bytes(bytes_length) }
      let(:iv) { SecureRandom.random_bytes(bytes_length) }

      describe 'encrypting and decrypting' do
        subject { described_class.new(xml_algorithm, key) }

        let(:uuid) { SecureRandom.uuid }

        specify { expect(subject.decrypt(subject.encrypt(uuid))).to eql(uuid) }
      end

      describe "decrypting #{algorithm} encrypted with the OpenSSL CLI" do
        subject { described_class.new(xml_algorithm, key, 0) }

        let(:encrypted_file) { Tempfile.new(algorithm).path }
        let(:original_file) { Tempfile.new("#{algorithm}-original").path }
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

      describe "when decrypting #{algorithm} with the OpenSSL CLI" do
        subject { described_class.new(xml_algorithm, key) }

        let(:encrypted_file) { Tempfile.new(algorithm).path }
        let(:decrypted_file) { Tempfile.new("#{algorithm}-decrypted").path }
        let(:secret) { SecureRandom.hex }

        before do
          IO.write(encrypted_file, subject.encrypt(secret))
          execute_shell([
            "openssl enc -#{openssl_algorithm} -p -d -nosalt",
            "-in #{encrypted_file}",
            "-out #{decrypted_file}",
            "-K #{key.unpack('H*')[0].upcase}",
            "-iv #{iv.unpack('H*')[0].upcase}"
          ].join(' '))
        end

        specify { expect(IO.read(decrypted_file)).to end_with(secret) }
      end
    end
  end
end
