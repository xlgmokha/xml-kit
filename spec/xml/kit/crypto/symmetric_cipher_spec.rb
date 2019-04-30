# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Crypto::SymmetricCipher do
  [
    'aes128-cbc',
    'aes192-cbc',
    'aes256-cbc',
    'tripledes-cbc',
  ].each do |algorithm|
    describe algorithm do
      let(:xml_algorithm) { "#{::Xml::Kit::Namespaces::XMLENC}#{algorithm}" }
      let(:openssl_algorithm) { Xml::Kit::Crypto::SymmetricCipher::ALGORITHMS[xml_algorithm].downcase }
      let(:key) { SecureRandom.random_bytes(cipher.key_len) }
      let(:iv) { SecureRandom.random_bytes(cipher.iv_len) }
      let(:cipher) { OpenSSL::Cipher.new(openssl_algorithm) }

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
        let(:data) { (iv.bytes + secret.bytes).pack('c*') }

        context 'when encoded as ASCII' do
          before do
            IO.write(original_file, data, encoding: Encoding::ASCII_8BIT)
            execute_shell([
              "openssl enc -#{openssl_algorithm} -p -e -A -nosalt",
              "-in #{original_file}",
              "-out #{encrypted_file}",
              "-K #{key.unpack1('H*').upcase}",
              "-iv #{iv.unpack1('H*').upcase}"
            ].join(' '))
          end

          specify do
            cipher_text = IO.read(encrypted_file, encoding: Encoding::ASCII_8BIT)
            expect(subject.decrypt(cipher_text)).to eql(secret)
          end
        end

        context 'when encoded as UTF-8' do
          before do
            IO.write(original_file, data)
            execute_shell([
              "openssl enc -#{openssl_algorithm} -p -e -A -nosalt",
              "-in #{original_file}",
              "-out #{encrypted_file}",
              "-K #{key.unpack1('H*').upcase}",
              "-iv #{iv.unpack1('H*').upcase}"
            ].join(' '))
          end

          specify do
            cipher_text = IO.read(encrypted_file)
            expect(subject.decrypt(cipher_text)).to eql(secret)
          end
        end
      end

      describe 'when decrypting with the OpenSSL CLI' do
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
            "-K #{key.unpack1('H*').upcase}",
            "-iv #{iv.unpack1('H*').upcase}"
          ].join(' '))
        end

        specify { expect(IO.read(decrypted_file)).to end_with(secret) }
      end
    end
  end
end
