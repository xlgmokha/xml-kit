# frozen_string_literal: true

RSpec.describe Xml::Kit::KeyPair do
  it 'ignores an empty passphrases' do
    expect do
      described_class.new(certificate, private_key, '', :signing)
    end.not_to raise_error(/OpenSSL::OpenSSLError/)
  end
end
