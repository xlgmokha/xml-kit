class Item
  include ::Xml::Kit::Templatable

  attr_reader :id, :signing_key_pair, :encryption_key_pair

  def initialize
    @id = ::Xml::Kit::Id.generate
    @signing_key_pair = ::Xml::Kit::KeyPair.generate(use: :signing)
    @embed_signature = true
    @encrypt = true
    @encryption_key_pair = ::Xml::Kit::KeyPair.generate(use: :encryption)
    @encryption_certificate = @encryption_key_pair.certificate
  end

  def template_path
    current_path = File.expand_path(File.dirname(__FILE__))
    File.join(current_path, "../fixtures/item.builder")
  end
end
