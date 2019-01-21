# frozen_string_literal: true

class Item
  include ::Xml::Kit::Templatable

  attr_reader :id, :signing_key_pair, :encryption_key_pair
  attr_accessor :template_path

  def initialize
    @id = ::Xml::Kit::Id.generate
    @signing_key_pair = ::Xml::Kit::KeyPair.generate(use: :signing)
    @embed_signature = true
    @encrypt = true
    @encryption_key_pair = ::Xml::Kit::KeyPair.generate(use: :encryption)
    @encryption_certificate = @encryption_key_pair.certificate
    @template_path = File.join(__dir__, '../fixtures/item.builder')
  end
end
